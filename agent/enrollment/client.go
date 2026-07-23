// Package enrollment bootstraps a private endpoint identity into Core's
// operator-approved enrollment workflow.
package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const stateSchema = "antiflock.agent-enrollment/v1"

type Config struct {
	Endpoint string
	Token string
	StateDirectory string
	NodeID string
	DisplayName string
	HTTP *http.Client
	Clock func() time.Time
}

type Result struct { EnrollmentID string; ProposedNodeID string; StateDirectory string }

type state struct { SchemaVersion string `json:"schemaVersion"`; NodeID string `json:"nodeId"`; RequestID string `json:"requestId"` }

func Submit(ctx context.Context, config Config) (Result, error) {
	if err := ctx.Err(); err != nil { return Result{}, err }
	endpoint, err := enrollmentEndpoint(config.Endpoint); if err != nil { return Result{}, err }
	if len(strings.TrimSpace(config.Token)) < 32 { return Result{}, errors.New("enrollment token is required") }
	if !canonical(config.NodeID, 128) || strings.TrimSpace(config.DisplayName) == "" || len(config.DisplayName) > 128 { return Result{}, errors.New("enrollment node id and display name are required") }
	clock := config.Clock; if clock == nil { clock = func() time.Time { return time.Now().UTC() } }
	privateKey, persisted, err := ensureIdentity(config.StateDirectory, config.NodeID); if err != nil { return Result{}, err }
	now := clock().UTC(); if now.IsZero() { return Result{}, errors.New("enrollment clock is invalid") }
	request := &antiflockv1.EnrollNodeRequest{
		TokenValue: strings.TrimSpace(config.Token), RequestId: persisted.RequestID, DisplayName: strings.TrimSpace(config.DisplayName),
		NodeType: antiflockv1.NodeType_NODE_TYPE_AGENT, Platform: runtime.GOOS, PlatformVersion: runtime.GOARCH, KeyAlgorithm: "ed25519",
		PublicKey: privateKey.Public().(ed25519.PublicKey), RequestedNodeId: config.NodeID, Capabilities: capabilityManifest(now),
	}
	proof, err := enrollment.ProofMessage(request); if err != nil { return Result{}, err }; request.ProofOfPossession = ed25519.Sign(privateKey, proof)
	body, err := (protojson.MarshalOptions{UseProtoNames: false}).Marshal(request); if err != nil { return Result{}, errors.New("encode enrollment request") }
	client := config.HTTP; if client == nil { client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }} }
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/enrollment/nodes", bytes.NewReader(body)); if err != nil { return Result{}, errors.New("build enrollment request") }; httpRequest.Header.Set("Content-Type","application/json"); httpRequest.Header.Set("Accept","application/json"); httpRequest.Header.Set("Accept-Encoding","identity")
	response, err := client.Do(httpRequest); if err != nil { return Result{}, fmt.Errorf("submit enrollment request: %w", err) }
	defer response.Body.Close(); content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20)); if err != nil || response.StatusCode != http.StatusAccepted { return Result{}, errors.New("Core did not accept enrollment request") }
	var output antiflockv1.EnrollNodeResponse; if err := (protojson.UnmarshalOptions{DiscardUnknown:false}).Unmarshal(content, &output); err != nil || output.GetEnrollment() == nil { return Result{}, errors.New("decode Core enrollment response") }
	return Result{EnrollmentID: output.GetEnrollment().GetId(), ProposedNodeID: output.GetEnrollment().GetProposedNodeId(), StateDirectory: config.StateDirectory}, nil
}

func capabilityManifest(now time.Time) *antiflockv1.CapabilityManifest {
	capability := &antiflockv1.Capability{Key:"network.metadata.observe", Domain:antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_NETWORK, Operations:[]antiflockv1.CapabilityOperation{antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE}, SupportLevel:antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL, Implementation:"antiflock-agent", ImplementationVersion:"v1", Constraints:[]string{"read-only","no-packet-payload"}, ObservedAt:timestamppb.New(now)}
	return &antiflockv1.CapabilityManifest{Revision:1, IssuedAt:timestamppb.New(now), ExpiresAt:timestamppb.New(now.Add(365*24*time.Hour)), Capabilities:[]*antiflockv1.Capability{capability}}
}

func ensureIdentity(directory, nodeID string) (ed25519.PrivateKey, state, error) {
	if strings.TrimSpace(directory)=="" { return nil,state{},errors.New("enrollment state directory is required") }; if err:=os.MkdirAll(directory,0o700);err!=nil{return nil,state{},errors.New("create enrollment state directory")}; if err:=os.Chmod(directory,0o700);err!=nil{return nil,state{},errors.New("protect enrollment state directory")}
	seedPath:=filepath.Join(directory,"node.seed"); statePath:=filepath.Join(directory,"enrollment.json")
	if content,err:=os.ReadFile(seedPath);err==nil { if len(content)!=ed25519.SeedSize{return nil,state{},errors.New("enrollment seed is invalid")}; loaded,err:=loadState(statePath,nodeID); if err!=nil{return nil,state{},err}; return ed25519.NewKeyFromSeed(content),loaded,nil } else if !errors.Is(err,os.ErrNotExist){return nil,state{},errors.New("read enrollment seed")}
	public,private,err:=ed25519.GenerateKey(rand.Reader); _=public; if err!=nil{return nil,state{},errors.New("generate enrollment seed")}; if err:=os.WriteFile(seedPath,private.Seed(),0o600);err!=nil{return nil,state{},errors.New("write enrollment seed")}
	requestID,err:=randomID("enroll");if err!=nil{return nil,state{},err}; value:=state{SchemaVersion:stateSchema,NodeID:nodeID,RequestID:requestID}; content,err:=json.Marshal(value);if err!=nil{return nil,state{},err};if err:=os.WriteFile(statePath,content,0o600);err!=nil{return nil,state{},errors.New("write enrollment state")};return private,value,nil
}

func loadState(path,nodeID string)(state,error){content,err:=os.ReadFile(path);if err!=nil{return state{},errors.New("read enrollment state")};var value state;if json.Unmarshal(content,&value)!=nil||value.SchemaVersion!=stateSchema||value.NodeID!=nodeID||!canonical(value.RequestID,128){return state{},errors.New("enrollment state is invalid")};return value,nil}
func randomID(prefix string)(string,error){raw:=make([]byte,12);if _,err:=rand.Read(raw);err!=nil{return "",err};return prefix+"-"+hex.EncodeToString(raw),nil}
func canonical(value string,maximum int)bool{return value!=""&&len(value)<=maximum&&strings.TrimSpace(value)==value&&!strings.ContainsAny(value,"\r\n\x00")}
func enrollmentEndpoint(raw string)(string,error){value,err:=url.Parse(strings.TrimSpace(raw));if err!=nil||value.Scheme==""||value.Host==""||value.User!=nil||value.RawQuery!=""||value.Fragment!=""||(value.Scheme!="https"&&value.Scheme!="http"){return "",errors.New("enrollment Core URL must be absolute HTTP(S)")};if value.Scheme=="http"&&!loopback(value.Hostname()){return "",errors.New("enrollment requires HTTPS outside loopback")};return strings.TrimRight(value.String(),"/"),nil}
func loopback(host string)bool{if strings.EqualFold(host,"localhost"){return true};ip:=net.ParseIP(host);return ip!=nil&&ip.IsLoopback()}
