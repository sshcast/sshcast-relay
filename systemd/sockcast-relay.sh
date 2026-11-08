# Export static Sockcast roaming SSH agent socket for interactive user sessions
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -f "${HOME}/.config/sockcast/relay.toml" ]; then
    export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/sockcast.sock"
fi
