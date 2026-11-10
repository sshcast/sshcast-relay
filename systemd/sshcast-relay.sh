# Export static Sshcast roaming SSH agent socket for interactive user sessions
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -f "${HOME}/.config/sshcast/relay.toml" ]; then
    export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/sshcast.sock"
fi
