//go:build linux

package sessionnet

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readSysctl returns the trimmed value of a /proc/sys entry, or "" if the
// entry does not exist on this kernel.
func readSysctl(name string) string {
	data, err := os.ReadFile("/proc/sys/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// userNamespacePolicyHint explains kernel policies that make a user
// namespace exist but deny it capabilities, which only shows up later.
func userNamespacePolicyHint() string {
	if readSysctl("kernel/apparmor_restrict_unprivileged_userns") == "1" {
		return " (AppArmor restricts unprivileged user namespaces: kernel.apparmor_restrict_unprivileged_userns=1; allow Yuhaiin with an AppArmor profile or disable the restriction)"
	}
	return ""
}

// classifyStartError turns a failed clone of the session helper into an
// actionable error. clone(2) only returns an errno, so the kernel's
// namespace sysctls are consulted to name the missing feature.
func classifyStartError(mode Mode, err error) error {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return &SetupError{Stage: StageHelper, Message: "cannot start the session helper", Err: err}
	}
	if mode == ModeRootless {
		if readSysctl("kernel/unprivileged_userns_clone") == "0" && os.Geteuid() != 0 {
			return &SetupError{Stage: StageUserNamespace, Err: err,
				Message: "User Namespace is disabled: unprivileged user namespaces are turned off (kernel.unprivileged_userns_clone=0); enable them with sysctl or use rootful mode"}
		}
		if readSysctl("user/max_user_namespaces") == "0" {
			return &SetupError{Stage: StageUserNamespace, Err: err,
				Message: "User Namespace is disabled: user.max_user_namespaces is 0; raise it with sysctl or use rootful mode"}
		}
	}
	for _, limit := range []struct {
		sysctl, name string
		stage        Stage
	}{
		{"user/max_pid_namespaces", "PID Namespace", StagePIDNamespace},
		{"user/max_net_namespaces", "Network Namespace", StageNamespaces},
		{"user/max_mnt_namespaces", "Mount Namespace", StageNamespaces},
	} {
		if readSysctl(limit.sysctl) == "0" {
			message := limit.name + " initialization failed: " + strings.ReplaceAll(limit.sysctl, "/", ".") + " is 0"
			if limit.stage == StagePIDNamespace {
				message = "PID Namespace initialization failed: user.max_pid_namespaces is 0, so the session process supervisor cannot be created"
			}
			return &SetupError{Stage: limit.stage, Err: err, Message: message}
		}
	}
	switch {
	case errno == unix.ENOSPC || errno == unix.EUSERS:
		return &SetupError{Stage: StageNamespaces, Err: err,
			Message: "Namespace initialization failed: the per-user namespace limit has been reached; close other sessions or raise the user.max_*_namespaces sysctls"}
	case errno == unix.EINVAL:
		return &SetupError{Stage: StageNamespaces, Err: err,
			Message: "Kernel features are missing: the kernel does not support user, network, mount or PID namespaces (CONFIG_USER_NS, CONFIG_NET_NS, CONFIG_PID_NS)"}
	case mode == ModeRootful && (errno == unix.EPERM || errno == unix.EACCES):
		return &SetupError{Stage: StageNamespaces, Err: err,
			Message: "Rootful mode requires root privileges (CAP_SYS_ADMIN and CAP_NET_ADMIN); run Yuhaiin as root or switch the SSH inbound to rootless mode"}
	case errno == unix.EPERM || errno == unix.EACCES:
		return &SetupError{Stage: StageUserNamespace, Err: err,
			Message: "User Namespace is disabled: creating a user namespace was denied by kernel policy, a seccomp filter or the container runtime"}
	case errno == unix.ENOENT || errno == unix.ENOEXEC:
		return &SetupError{Stage: StageHelper, Err: err, Message: "cannot execute the session helper binary"}
	}
	return &SetupError{Stage: StageNamespaces, Err: err, Message: "Namespace initialization failed"}
}
