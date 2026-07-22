package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
)

var currentPathEventKinds = []string{
	"mesh.connection_lost", "mesh.exit_changed", "mesh.path_changed",
	"network.dns_changed", "network.gateway_changed", "network.route_changed", "network.wifi_changed",
}

type durablePathFact struct {
	event   model.EventEnvelope
	payload proto.Message
}

type durablePathFacts struct {
	wifi    *durablePathFact
	gateway *durablePathFact
	route   *durablePathFact
	dns     *durablePathFact
	mesh    *durablePathFact
}

type nodeView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Platform     string   `json:"platform"`
	State        string   `json:"state"`
	Protection   string   `json:"protection"`
	LastSeen     string   `json:"lastSeen"`
	Network      string   `json:"network"`
	MeshAddress  string   `json:"meshAddress"`
	MeshState    string   `json:"meshState"`
	CurrentExit  string   `json:"currentExit"`
	DNSState     string   `json:"dnsState"`
	AgentVersion string   `json:"agentVersion"`
	Capabilities []string `json:"capabilities"`
	Tags         []string `json:"tags"`
}

func (server *Server) handleOverview(response http.ResponseWriter, request *http.Request) {
	nodes, err := server.database.ListNodes(request.Context())
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	now := server.clock().UTC()
	protected := 0
	var overviewFacts durablePathFacts
	var overviewObservedAt time.Time
	for _, node := range nodes {
		if server.actions.posture(node.ID, now).State == "PROTECTED" {
			protected++
		}
		facts, loadErr := server.loadDurablePathFacts(request.Context(), node.ID)
		if loadErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, loadErr, "")
			return
		}
		if observedAt := server.latestFreshPathFactAt(facts, now); observedAt.After(overviewObservedAt) {
			overviewFacts, overviewObservedAt = facts, observedAt
		}
	}
	heldActions, err := server.database.CountSecureActionsByDecision(request.Context(), "HOLD")
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	environment, currentExit, exitVerified, dnsState, dnsResolver := server.overviewPathProjection(overviewFacts, overviewObservedAt, now)
	writeJSON(response, http.StatusOK, map[string]any{
		"operatorName": "Local operator", "deploymentName": server.deploymentID,
		"environment":      environment,
		"protectedDevices": protected, "totalDevices": len(nodes),
		"openFindings": len(server.findings.List("", antiflockv1.FindingStatus_FINDING_STATUS_OPEN)), "heldActions": heldActions,
		"currentExit": currentExit, "exitVerified": exitVerified, "dnsState": dnsState,
		"dnsResolver": dnsResolver, "scramblerState": "IDLE", "version": server.version,
	})
}

func (server *Server) handleNodes(response http.ResponseWriter, request *http.Request) {
	nodes, err := server.database.ListNodes(request.Context())
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	now := server.clock().UTC()
	result := make([]nodeView, 0, len(nodes))
	for _, node := range nodes {
		facts, loadErr := server.loadDurablePathFacts(request.Context(), node.ID)
		if loadErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, loadErr, "")
			return
		}
		result = append(result, server.nodeProjectionWithFacts(node, facts, now))
	}
	writeJSON(response, http.StatusOK, map[string]any{"nodes": result})
}

func (server *Server) nodeProjection(node model.Node, now time.Time) nodeView {
	return server.nodeProjectionWithFacts(node, durablePathFacts{}, now)
}

func (server *Server) nodeProjectionWithFacts(node model.Node, facts durablePathFacts, now time.Time) nodeView {
	lastSeen := node.EnrolledAt
	state := "stale"
	if node.LastSeenAt != nil {
		lastSeen = *node.LastSeenAt
		if now.Sub(lastSeen) <= server.config.Protection.TelemetryStaleAfter {
			state = "online"
		}
	}
	if node.Status != model.NodeActive {
		state = "blocked"
	}
	network, meshState, currentExit, dnsState := "Unknown", "UNKNOWN", "Unknown", "UNKNOWN"
	if server.pathFactFresh(facts.wifi, now) {
		wifi, _ := pathPayload[*antiflockv1.WifiObservation](facts.wifi)
		network = enumSuffix(wifi.GetTrust().String(), "NETWORK_TRUST_") + " Wi-Fi (" + enumSuffix(wifi.GetSecurity().String(), "WIFI_SECURITY_") + ")"
	} else if server.pathFactFresh(facts.gateway, now) {
		gateway, _ := pathPayload[*antiflockv1.GatewayObservation](facts.gateway)
		network = enumSuffix(gateway.GetTrust().String(), "NETWORK_TRUST_") + " network"
	}
	if server.pathFactFresh(facts.mesh, now) {
		mesh, _ := pathPayload[*antiflockv1.MeshPathObservation](facts.mesh)
		meshState = enumSuffix(mesh.GetConnectionType().String(), "MESH_CONNECTION_TYPE_")
		if mesh.GetExitNodeId() != "" {
			currentExit = mesh.GetExitNodeId()
		} else if mesh.GetDestinationNodeId() != "" {
			currentExit = mesh.GetDestinationNodeId()
		}
	}
	if server.pathFactFresh(facts.dns, now) {
		dns, _ := pathPayload[*antiflockv1.DnsObservation](facts.dns)
		if dns.GetPathVerified() && facts.dns.event.Classification == model.EvidenceVerified {
			dnsState = "VERIFIED"
		} else if dns.GetPathVerified() {
			dnsState = "OBSERVED"
		} else {
			dnsState = "UNPROTECTED"
		}
	}
	return nodeView{
		ID: node.ID, Name: node.Name, Kind: strings.ToLower(node.Type), Platform: node.Platform,
		State: state, Protection: server.actions.posture(node.ID, now).State,
		LastSeen: lastSeen.UTC().Format(time.RFC3339Nano), Network: network,
		MeshAddress: "Unknown", MeshState: meshState, CurrentExit: currentExit, DNSState: dnsState,
		AgentVersion: "Unknown", Capabilities: []string{},
		Tags: append([]string(nil), node.Tags...),
	}
}

func (server *Server) handlePosture(response http.ResponseWriter, _ *http.Request) {
	postures := server.actions.allPostures(server.clock().UTC())
	if len(postures) == 0 {
		unknown := unknownPosture("unavailable", server.clock().UTC(), "AF-POSTURE-UNAVAILABLE")
		writeJSON(response, http.StatusOK, map[string]any{
			"state": unknown.State, "reasonCode": unknown.ReasonCodes[0],
			"summary": "No fresh endpoint posture has been reported.", "evaluatedAt": unknown.ObservedAt,
			"confidence": 1, "evidenceClass": "Unknown", "checks": []any{},
		})
		return
	}
	posture := postures[0]
	reason := ""
	if len(posture.ReasonCodes) != 0 {
		reason = posture.ReasonCodes[0]
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"state": posture.State, "reasonCode": reason, "summary": postureSummary(posture),
		"evaluatedAt": posture.ObservedAt, "confidence": posture.Confidence, "evidenceClass": evidenceClassFor(posture),
		"nodeId": posture.NodeID, "policyRevision": posture.PolicyRevision, "checks": postureChecks(posture),
	})
}

func postureSummary(posture protectionView) string {
	switch posture.State {
	case "PROTECTED":
		return "Required mesh, exit, and DNS controls are freshly verified."
	case "EXPOSED":
		return "A required protection is absent; protected actions remain held."
	case "UNKNOWN", "UNAVAILABLE":
		return "Current evidence is insufficient to verify the protected path."
	default:
		return "Protection is operating with a condition that requires review."
	}
}

func postureChecks(posture protectionView) []map[string]any {
	checks := []struct {
		id       string
		label    string
		value    *bool
		expected string
	}{
		{"mesh", "Private mesh", posture.MeshConnected, "Connected"},
		{"exit", "Approved exit", posture.ApprovedExitActive, "Active"},
		{"dns", "Protected DNS", posture.DNSProtected, "Verified"},
		{"route", "Protected route", posture.RouteProtected, "Active"},
	}
	result := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		state, observed := "unknown", "Not reported"
		if check.value != nil {
			if *check.value {
				state, observed = "pass", "Verified"
			} else {
				state, observed = "fail", "Not active"
			}
		}
		result = append(result, map[string]any{
			"id": check.id, "label": check.label, "state": state, "observed": observed,
			"expected": check.expected, "evidenceClass": evidenceClassFor(posture), "checkedAt": posture.ObservedAt,
		})
	}
	return result
}

func (server *Server) handleEmptyList(key string) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{key: []any{}})
	}
}

func (server *Server) handleFootprint(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{"assets": []any{}, "relationships": []any{}})
}

func (server *Server) handleTopology(response http.ResponseWriter, request *http.Request) {
	nodes, err := server.database.ListNodes(request.Context())
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	now := server.clock().UTC()
	entities := make([]map[string]any, 0, len(nodes))
	nodeViews := make([]nodeView, 0, len(nodes))
	observations := make([]map[string]any, 0, len(nodes)*4)
	relationships := make([]map[string]any, 0)
	enrolled := make(map[string]struct{}, len(nodes))
	factsByNode := make(map[string]durablePathFacts, len(nodes))
	for _, node := range nodes {
		enrolled[node.ID] = struct{}{}
		entities = append(entities, map[string]any{
			"id": node.ID, "type": "NODE", "displayName": node.Name, "nodeType": node.Type,
			"platform": node.Platform, "status": node.Status, "enrolledAt": node.EnrolledAt.UTC().Format(time.RFC3339Nano),
		})
		facts, loadErr := server.loadDurablePathFacts(request.Context(), node.ID)
		if loadErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, loadErr, "")
			return
		}
		factsByNode[node.ID] = facts
		nodeViews = append(nodeViews, server.nodeProjectionWithFacts(node, facts, now))
		observations = append(observations, server.pathFactViews(node.ID, facts, now)...)
	}
	for _, node := range nodes {
		fact := factsByNode[node.ID].mesh
		if fact == nil || !server.pathFactFresh(fact, now) {
			continue
		}
		mesh, ok := fact.payload.(*antiflockv1.MeshPathObservation)
		if !ok || mesh.GetSourceNodeId() != node.ID || mesh.GetDestinationNodeId() == "" ||
			!meshConnectionActive(mesh) || !mesh.GetTunnelHealthy() {
			continue
		}
		if _, exists := enrolled[mesh.GetDestinationNodeId()]; !exists {
			// An exit or peer identifier is still shown as an observed fact, but
			// it is not promoted into the enrolled-node topology as an asset.
			continue
		}
		relationships = append(relationships, map[string]any{
			"id": meshRelationshipID(fact.event, mesh), "type": "MESH_PATH",
			"sourceEntityId": mesh.GetSourceNodeId(), "targetEntityId": mesh.GetDestinationNodeId(),
			"state": "ACTIVE", "classification": fact.event.Classification, "confidence": fact.event.Confidence,
			"observedAt": fact.event.ObservedAt.UTC().Format(time.RFC3339Nano), "evidenceEventId": fact.event.ID,
		})
	}
	sort.Slice(relationships, func(left, right int) bool {
		return relationships[left]["id"].(string) < relationships[right]["id"].(string)
	})
	state := "OBSERVED"
	reasonCodes := []string{}
	if len(observations) == 0 {
		state = "UNKNOWN"
		reasonCodes = append(reasonCodes, "AF-TOPOLOGY-NO-DURABLE-OBSERVATIONS")
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"state": state, "reasonCodes": reasonCodes, "evaluatedAt": now.Format(time.RFC3339Nano),
		"nodes": nodeViews, "entities": entities, "relationships": relationships, "observations": observations,
	})
}

func (server *Server) handlePaths(response http.ResponseWriter, request *http.Request) {
	requestedNodeID := strings.TrimSpace(request.URL.Query().Get("nodeId"))
	if requestedNodeID != "" && !bounded(requestedNodeID, 128) {
		writeAPIError(response, http.StatusBadRequest, "INVALID_NODE", "Path node id is invalid.", "", false)
		return
	}
	nodes, err := server.database.ListNodes(request.Context())
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	now := server.clock().UTC()
	paths := make([]map[string]any, 0, len(nodes))
	found := requestedNodeID == ""
	for _, node := range nodes {
		if requestedNodeID != "" && node.ID != requestedNodeID {
			continue
		}
		found = true
		facts, loadErr := server.loadDurablePathFacts(request.Context(), node.ID)
		if loadErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, loadErr, "")
			return
		}
		paths = append(paths, server.currentPathView(node, facts, now))
	}
	if !found {
		server.writeDomainError(response, http.StatusNotFound, storage.ErrNodeNotFound, "")
		return
	}
	reasonCodes := []string{}
	if len(paths) == 0 {
		reasonCodes = append(reasonCodes, "AF-PATH-NODE-UNAVAILABLE")
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"paths": paths, "reasonCodes": reasonCodes, "evaluatedAt": now.Format(time.RFC3339Nano),
	})
}

func (server *Server) loadDurablePathFacts(ctx context.Context, nodeID string) (durablePathFacts, error) {
	events, err := server.database.ListLatestEventsForNode(ctx, nodeID, currentPathEventKinds)
	if err != nil {
		return durablePathFacts{}, err
	}
	var facts durablePathFacts
	for _, event := range events {
		var destination **durablePathFact
		var payload proto.Message
		switch event.Kind {
		case "network.wifi_changed":
			payload, destination = &antiflockv1.WifiObservation{}, &facts.wifi
		case "network.gateway_changed":
			payload, destination = &antiflockv1.GatewayObservation{}, &facts.gateway
		case "network.route_changed":
			payload, destination = &antiflockv1.RouteObservation{}, &facts.route
		case "network.dns_changed":
			payload, destination = &antiflockv1.DnsObservation{}, &facts.dns
		case "mesh.connection_lost", "mesh.exit_changed", "mesh.path_changed":
			payload, destination = &antiflockv1.MeshPathObservation{}, &facts.mesh
		default:
			continue
		}
		if err := proto.Unmarshal(event.Payload, payload); err != nil {
			return durablePathFacts{}, errors.New("stored path observation payload is invalid")
		}
		candidate := &durablePathFact{event: event, payload: payload}
		if *destination == nil || pathFactAfter(candidate, *destination) {
			*destination = candidate
		}
	}
	return facts, nil
}

func pathFactAfter(candidate, current *durablePathFact) bool {
	return candidate.event.ObservedAt.After(current.event.ObservedAt) ||
		(candidate.event.ObservedAt.Equal(current.event.ObservedAt) && candidate.event.IngestOrdinal > current.event.IngestOrdinal)
}

func (server *Server) pathFactFresh(fact *durablePathFact, now time.Time) bool {
	return fact != nil && !fact.event.ObservedAt.After(now.Add(5*time.Minute)) &&
		!fact.event.ObservedAt.Before(now.Add(-server.config.Protection.TelemetryStaleAfter))
}

func (server *Server) latestFreshPathFactAt(facts durablePathFacts, now time.Time) time.Time {
	var latest time.Time
	for _, fact := range []*durablePathFact{facts.wifi, facts.gateway, facts.route, facts.mesh, facts.dns} {
		if server.pathFactFresh(fact, now) && fact.event.ObservedAt.After(latest) {
			latest = fact.event.ObservedAt
		}
	}
	return latest
}

func (server *Server) overviewPathProjection(facts durablePathFacts, observedAt, now time.Time) (map[string]any, string, bool, string, string) {
	environment := map[string]any{
		"name": "Unknown", "type": "unknown", "trust": "UNKNOWN", "security": "Unknown",
		"known": false, "gateway": "Unknown", "changedAt": "",
	}
	if !observedAt.IsZero() {
		environment["changedAt"] = observedAt.UTC().Format(time.RFC3339Nano)
	}
	if server.pathFactFresh(facts.wifi, now) {
		wifi, _ := pathPayload[*antiflockv1.WifiObservation](facts.wifi)
		environment["name"] = "Wi-Fi network (identifier withheld)"
		environment["type"] = "wifi"
		environment["trust"] = enumSuffix(wifi.GetTrust().String(), "NETWORK_TRUST_")
		environment["security"] = enumSuffix(wifi.GetSecurity().String(), "WIFI_SECURITY_")
		environment["known"] = wifi.GetKnownNetwork()
		environment["changedAt"] = facts.wifi.event.ObservedAt.UTC().Format(time.RFC3339Nano)
	} else if server.pathFactFresh(facts.gateway, now) {
		gateway, _ := pathPayload[*antiflockv1.GatewayObservation](facts.gateway)
		environment["name"] = "Observed network"
		environment["type"] = "network"
		environment["trust"] = enumSuffix(gateway.GetTrust().String(), "NETWORK_TRUST_")
		environment["changedAt"] = facts.gateway.event.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	if server.pathFactFresh(facts.gateway, now) {
		gateway, _ := pathPayload[*antiflockv1.GatewayObservation](facts.gateway)
		if gateway.GetAddress() != "" {
			environment["gateway"] = gateway.GetAddress()
		} else {
			environment["gateway"] = "Observed (address unavailable)"
		}
	}

	currentExit, exitVerified := "Unknown", false
	if server.pathFactFresh(facts.mesh, now) {
		mesh, _ := pathPayload[*antiflockv1.MeshPathObservation](facts.mesh)
		if mesh.GetExitNodeId() != "" {
			currentExit = mesh.GetExitNodeId()
		} else if mesh.GetDestinationNodeId() != "" {
			currentExit = mesh.GetDestinationNodeId()
		}
		exitVerified = facts.mesh.event.Classification == model.EvidenceVerified && meshFactActive(facts.mesh)
	}
	dnsState, dnsResolver := "UNKNOWN", "Unknown"
	if server.pathFactFresh(facts.dns, now) {
		dns, _ := pathPayload[*antiflockv1.DnsObservation](facts.dns)
		switch {
		case dns.GetPathVerified() && facts.dns.event.Classification == model.EvidenceVerified:
			dnsState = "VERIFIED"
		case dns.GetPathVerified():
			dnsState = "OBSERVED"
		default:
			dnsState = "UNPROTECTED"
		}
		if len(dns.GetResolverAddresses()) != 0 {
			dnsResolver = dns.GetResolverAddresses()[0]
		} else if dns.GetSource() != "" {
			dnsResolver = "Observed via " + dns.GetSource()
		}
	}
	return environment, currentExit, exitVerified, dnsState, dnsResolver
}

func (server *Server) pathFactViews(nodeID string, facts durablePathFacts, now time.Time) []map[string]any {
	result := make([]map[string]any, 0, 5)
	for _, fact := range []*durablePathFact{facts.wifi, facts.gateway, facts.route, facts.mesh, facts.dns} {
		if fact == nil {
			continue
		}
		view := map[string]any{
			"id": fact.event.ID, "nodeId": nodeID, "kind": fact.event.Kind,
			"observedAt":     fact.event.ObservedAt.UTC().Format(time.RFC3339Nano),
			"classification": fact.event.Classification, "confidence": fact.event.Confidence,
			"fresh": server.pathFactFresh(fact, now), "details": pathFactDetails(fact),
		}
		if !server.pathFactFresh(fact, now) {
			view["state"] = "STALE"
		} else if fact.event.Classification == model.EvidenceVerified {
			view["state"] = "VERIFIED"
		} else {
			view["state"] = "OBSERVED"
		}
		result = append(result, view)
	}
	return result
}

func pathFactDetails(fact *durablePathFact) map[string]any {
	switch payload := fact.payload.(type) {
	case *antiflockv1.WifiObservation:
		return map[string]any{
			"trust":        enumSuffix(payload.GetTrust().String(), "NETWORK_TRUST_"),
			"security":     enumSuffix(payload.GetSecurity().String(), "WIFI_SECURITY_"),
			"knownNetwork": payload.GetKnownNetwork(),
		}
	case *antiflockv1.GatewayObservation:
		return map[string]any{
			"interfaceId": payload.GetInterfaceId(), "address": payload.GetAddress(),
			"trust": enumSuffix(payload.GetTrust().String(), "NETWORK_TRUST_"),
		}
	case *antiflockv1.RouteObservation:
		return map[string]any{
			"routeId": payload.GetRouteId(), "destination": payload.GetDestination(),
			"gateway": payload.GetGateway(), "interfaceId": payload.GetInterfaceId(),
			"defaultRoute": payload.GetDefaultRoute(), "policyRoute": payload.GetPolicyRoute(),
		}
	case *antiflockv1.DnsObservation:
		return map[string]any{
			"resolverAddresses": append([]string(nil), payload.GetResolverAddresses()...),
			"source":            payload.GetSource(), "pathVerified": payload.GetPathVerified(),
		}
	case *antiflockv1.MeshPathObservation:
		return map[string]any{
			"pathId": payload.GetPathId(), "provider": payload.GetProvider(),
			"sourceNodeId": payload.GetSourceNodeId(), "destinationNodeId": payload.GetDestinationNodeId(),
			"connectionType": enumSuffix(payload.GetConnectionType().String(), "MESH_CONNECTION_TYPE_"),
			"exitNodeId":     payload.GetExitNodeId(), "approvedExitActive": payload.GetApprovedExitActive(),
			"tunnelHealthy": payload.GetTunnelHealthy(),
		}
	default:
		return map[string]any{}
	}
}

func (server *Server) currentPathView(node model.Node, facts durablePathFacts, now time.Time) map[string]any {
	posture := server.actions.posture(node.ID, now)
	checks := []map[string]any{
		server.pathCheck("local-network", "Local network observed", firstPathFact(facts.wifi, facts.gateway), true, now),
		server.pathCheck("route", "Current route observed", facts.route, routeFactActive(facts.route), now),
		server.pathCheck("mesh", "Approved mesh exit active", facts.mesh, meshFactActive(facts.mesh), now),
		server.pathCheck("dns", "Protected DNS path observed", facts.dns, dnsFactActive(facts.dns), now),
	}
	reasonCodes := append([]string(nil), posture.ReasonCodes...)
	missingCodes := []string{"AF-PATH-LOCAL-UNKNOWN", "AF-PATH-ROUTE-UNKNOWN", "AF-PATH-MESH-UNKNOWN", "AF-PATH-DNS-UNKNOWN"}
	for index, check := range checks {
		state := check["state"].(string)
		switch state {
		case "UNKNOWN":
			reasonCodes = appendUnique(reasonCodes, missingCodes[index])
		case "STALE":
			reasonCodes = appendUnique(reasonCodes, "AF-PATH-EVIDENCE-STALE")
		case "FAIL":
			reasonCodes = appendUnique(reasonCodes, strings.Replace(missingCodes[index], "UNKNOWN", "INACTIVE", 1))
		}
	}
	hops := make([]map[string]any, 0, 5)
	for _, item := range []struct {
		role string
		fact *durablePathFact
	}{
		{"LOCAL_NETWORK", firstPathFact(facts.wifi, facts.gateway)},
		{"ROUTE", facts.route}, {"MESH_EXIT", facts.mesh}, {"DNS", facts.dns},
	} {
		if item.fact == nil {
			continue
		}
		hops = append(hops, map[string]any{
			"position": len(hops) + 1, "logicalRole": item.role, "evidenceEventId": item.fact.event.ID,
			"kind": item.fact.event.Kind, "classification": item.fact.event.Classification,
			"confidence": item.fact.event.Confidence, "fresh": server.pathFactFresh(item.fact, now),
			"observedAt": item.fact.event.ObservedAt.UTC().Format(time.RFC3339Nano), "details": pathFactDetails(item.fact),
		})
	}
	observedAt := node.EnrolledAt
	for _, fact := range []*durablePathFact{facts.wifi, facts.gateway, facts.route, facts.mesh, facts.dns} {
		if fact != nil && fact.event.ObservedAt.After(observedAt) {
			observedAt = fact.event.ObservedAt
		}
	}
	complete := true
	for _, check := range checks {
		if state := check["state"].(string); state == "UNKNOWN" || state == "STALE" {
			complete = false
		}
	}
	return map[string]any{
		"id": "current-path:" + node.ID, "sourceNodeId": node.ID, "state": posture.State,
		"summary": currentPathSummary(posture.State, complete), "reasonCodes": reasonCodes,
		"observedAt": observedAt.UTC().Format(time.RFC3339Nano), "completeVisibility": complete,
		"hops": hops, "checks": checks,
	}
}

func (server *Server) pathCheck(id, label string, fact *durablePathFact, active bool, now time.Time) map[string]any {
	result := map[string]any{"id": id, "label": label, "state": "UNKNOWN", "known": false}
	if fact == nil {
		return result
	}
	result["known"] = true
	result["evidenceEventId"] = fact.event.ID
	result["classification"] = fact.event.Classification
	result["observedAt"] = fact.event.ObservedAt.UTC().Format(time.RFC3339Nano)
	if !server.pathFactFresh(fact, now) {
		result["state"] = "STALE"
	} else if !active {
		result["state"] = "FAIL"
	} else if fact.event.Classification == model.EvidenceVerified {
		result["state"] = "PASS"
	} else {
		result["state"] = "OBSERVED"
	}
	return result
}

func firstPathFact(primary, fallback *durablePathFact) *durablePathFact {
	if primary != nil {
		return primary
	}
	return fallback
}

func routeFactActive(fact *durablePathFact) bool {
	payload, ok := pathPayload[*antiflockv1.RouteObservation](fact)
	return ok && (payload.GetDefaultRoute() || payload.GetPolicyRoute())
}

func dnsFactActive(fact *durablePathFact) bool {
	payload, ok := pathPayload[*antiflockv1.DnsObservation](fact)
	return ok && payload.GetPathVerified()
}

func meshFactActive(fact *durablePathFact) bool {
	payload, ok := pathPayload[*antiflockv1.MeshPathObservation](fact)
	return ok && meshConnectionActive(payload) && payload.GetApprovedExitActive() && payload.GetTunnelHealthy()
}

func pathPayload[T proto.Message](fact *durablePathFact) (T, bool) {
	var zero T
	if fact == nil {
		return zero, false
	}
	payload, ok := fact.payload.(T)
	return payload, ok
}

func meshConnectionActive(payload *antiflockv1.MeshPathObservation) bool {
	return payload.GetConnectionType() == antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DIRECT ||
		payload.GetConnectionType() == antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_RELAYED
}

func meshRelationshipID(event model.EventEnvelope, payload *antiflockv1.MeshPathObservation) string {
	pathID := payload.GetPathId()
	if pathID == "" {
		pathID = event.ID
	}
	return "mesh:" + payload.GetSourceNodeId() + ":" + payload.GetDestinationNodeId() + ":" + pathID
}

func enumSuffix(value, prefix string) string {
	return strings.TrimPrefix(value, prefix)
}

func appendUnique(values []string, value string) []string {
	if !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}

func currentPathSummary(state string, complete bool) string {
	if !complete {
		return "Current path visibility is incomplete; unknown or stale facts are shown explicitly."
	}
	switch state {
	case "PROTECTED":
		return "Fresh durable observations support the currently protected network path."
	case "EXPOSED":
		return "The current network path is observed, but a required protection is inactive."
	default:
		return "The current network path is observed, but its protection state is not verified."
	}
}

func (server *Server) handleScrambler(response http.ResponseWriter, request *http.Request) {
	nodeID := strings.TrimSpace(request.URL.Query().Get("nodeId"))
	var node model.Node
	var err error
	if nodeID != "" {
		if !bounded(nodeID, 128) {
			writeAPIError(response, http.StatusBadRequest, "INVALID_NODE", "Scrambler node id is invalid.", "", false)
			return
		}
		node, err = server.database.GetNode(request.Context(), nodeID)
	} else {
		nodes, listErr := server.database.ListNodes(request.Context())
		if listErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, listErr, "")
			return
		}
		if len(nodes) == 0 {
			writeJSON(response, http.StatusOK, map[string]any{
				"state": "UNAVAILABLE", "profile": "none", "stateId": "", "nodeId": "",
				"currentExit": "Not configured", "lastTransitionAt": time.Unix(0, 0).UTC().Format(time.RFC3339Nano),
				"simulationOnly": true, "risk": "unknown", "reasonCodes": []string{"AF-NODE-UNAVAILABLE"}, "checks": []any{},
			})
			return
		}
		node = nodes[0]
	}
	if err != nil {
		status := http.StatusInternalServerError
		if err == storage.ErrNodeNotFound {
			status = http.StatusNotFound
		}
		server.writeDomainError(response, status, err, "")
		return
	}
	state := server.scramblerState(node.ID, node.EnrolledAt)
	writeJSON(response, http.StatusOK, map[string]any{
		"state": "IDLE", "profile": "none", "stateId": state.GetId(), "nodeId": node.ID,
		"currentExit": "Not configured", "lastTransitionAt": node.EnrolledAt.UTC().Format(time.RFC3339Nano),
		"simulationOnly": !server.config.Scrambler.ExecutionEnabled, "risk": "low",
		"reasonCodes": state.GetReasonCodes(), "checks": []any{},
	})
}

func eventLimit(request *http.Request) (int, error) {
	value := request.URL.Query().Get("limit")
	if value == "" {
		return 100, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 500 {
		return 0, strconv.ErrSyntax
	}
	return limit, nil
}
