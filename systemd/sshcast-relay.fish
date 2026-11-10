# Export static Sshcast roaming SSH agent socket for interactive fish sessions
if set -q XDG_RUNTIME_DIR; and test -f "$HOME/.config/sshcast/relay.toml"
    set -gx SSH_AUTH_SOCK "$XDG_RUNTIME_DIR/sshcast.sock"
end
