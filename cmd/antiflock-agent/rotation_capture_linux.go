package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
	"github.com/DBarr3/AntiFlock/internal/agentcli"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

var errPrivateCaptureDirectory = errors.New("capture requires a real private directory owned by the capture user")

func captureRotation(ctx context.Context, configPath, intentPath, output string, enrollment collectors.RotationEnrollment, stdout io.Writer) error {
	directory, err := openCaptureDestination(output)
	if err != nil {
		return err
	}
	defer directory.Close()

	config, _, err := agentcli.LoadConfig(configPath)
	if err != nil {
		return errors.New("capture observer config refused")
	}
	raw, err := readRotationIntentFile(intentPath)
	if err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return errors.New("read kernel boot identity")
	}
	bootID := strings.TrimSpace(string(boot))
	if len(bootID) != 36 {
		return errors.New("kernel boot identity refused")
	}
	signer, err := agentruntime.LoadFileSigner(config.NodeID, config.KeyPath(), nil)
	if err != nil {
		return err
	}
	queue, err := agentruntime.OpenQueue(config.QueueDir, config.NodeID)
	if err != nil {
		return err
	}
	defer queue.Close()
	builder, err := collectors.NewTelemetryBuilder(config.DeploymentID, config.NodeID, bootID, queue, signer, nil)
	if err != nil {
		return err
	}
	event, err := builder.CaptureRotationRoute(ctx, raw, enrollment)
	if err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		return errors.New("encode rotation route observation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writePrivateCapture(directory, filepath.Base(output), encoded); err != nil {
		return err
	}
	_, err = io.WriteString(stdout, "Private rotation route observation captured\n")
	return err
}

func openPrivateCaptureDirectory(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errPrivateCaptureDirectory
	}
	const traverse = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", traverse, 0)
	if err != nil {
		return nil, errPrivateCaptureDirectory
	}
	for part := range strings.SplitSeq(strings.TrimPrefix(absolute, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, traverse, 0)
		unix.Close(fd)
		if err != nil {
			return nil, errPrivateCaptureDirectory
		}
		fd = next
	}
	directory, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, errPrivateCaptureDirectory
	}
	var stat unix.Stat_t
	if err := unix.Fstat(directory, &stat); err != nil ||
		stat.Mode&0o777 != agentcli.PrivateDirectoryMode || stat.Uid != uint32(os.Geteuid()) {
		unix.Close(directory)
		return nil, errPrivateCaptureDirectory
	}
	return os.NewFile(uintptr(directory), absolute), nil
}

func readRotationIntentFile(path string) ([]byte, error) {
	const limit = collectors.MaxRotationIntentBytes
	if strings.HasSuffix(path, "/") {
		return nil, errors.New("rotation intent must be a bounded regular file")
	}
	directory, err := openPrivateCaptureDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	dirFD, name := int(directory.Fd()), filepath.Base(path)
	var before unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 1 || before.Size > limit {
		return nil, errors.New("rotation intent must be a bounded regular file")
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("read rotation intent")
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if !sameRotationIntent(fd, before) {
		return nil, errors.New("rotation intent changed before reading")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) != int(before.Size) || !sameRotationIntent(fd, before) {
		return nil, errors.New("rotation intent changed while reading")
	}
	return raw, nil
}

func sameRotationIntent(fd int, before unix.Stat_t) bool {
	var current unix.Stat_t
	return unix.Fstat(fd, &current) == nil && current.Dev == before.Dev && current.Ino == before.Ino &&
		current.Mode == before.Mode && current.Size == before.Size && current.Mtim == before.Mtim && current.Ctim == before.Ctim
}

func openCaptureDestination(path string) (*os.File, error) {
	if strings.HasSuffix(path, "/") {
		return nil, errors.New("capture destination must be a new file")
	}
	directory, err := openPrivateCaptureDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		directory.Close()
		return nil, errors.New("capture destination must not exist")
	}
	return directory, nil
}

func captureDirectoryCurrent(directory *os.File) bool {
	current, err := openPrivateCaptureDirectory(directory.Name())
	if err != nil {
		return false
	}
	defer current.Close()
	before, beforeErr := directory.Stat()
	after, afterErr := current.Stat()
	return beforeErr == nil && afterErr == nil && os.SameFile(before, after)
}

func writePrivateCapture(directory *os.File, name string, encoded []byte) error {
	if !captureDirectoryCurrent(directory) {
		return errors.New("capture directory changed before publication")
	}
	dirFD := int(directory.Fd())
	staged := ".rotation-capture-" + rand.Text()
	fd, err := unix.Openat(dirFD, staged, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return errors.New("stage private route capture")
	}
	defer unix.Unlinkat(dirFD, staged, 0)
	file := os.NewFile(uintptr(fd), staged)
	defer file.Close()
	if err := file.Chmod(agentcli.PrivateFileMode); err != nil {
		return errors.New("set private route capture permissions")
	}
	if _, err := file.Write(encoded); err != nil {
		return errors.New("write private route capture")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync private route capture")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private route capture")
	}
	if err := unix.Linkat(dirFD, staged, dirFD, name, 0); err != nil {
		return errors.New("publish new private route capture")
	}
	if err := unix.Unlinkat(dirFD, staged, 0); err != nil {
		return errors.New("private route capture published but staging cleanup failed")
	}
	if err := directory.Sync(); err != nil {
		return errors.New("private route capture published but directory sync failed")
	}
	if !captureDirectoryCurrent(directory) {
		return errors.New("capture directory moved during publication")
	}
	return nil
}
