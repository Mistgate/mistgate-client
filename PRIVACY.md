# Privacy

Mistgate for Windows has no analytics, no telemetry and no account of its own. It talks to the network only for the
things below. Nothing about the sites you open or the programs you run is sent to anyone.

## What the app connects to, and when

| What | When | What goes out |
|:--|:--|:--|
| Your subscription's address (your provider's panel) | When you add the subscription, when you press Update, and on the provider's own refresh interval | The link you pasted, the app's name and version, and an identifier of this installation made for that provider (so the provider can count devices). On a Mistgate panel the app enrols the PC with a device key it generates |
| Your VPN servers | While you are connected, when you measure latency, and during a network check | The VPN traffic itself and the handshakes of the protocols |
| This project's GitHub releases | A little after the app starts and four times a day, while "Install updates automatically" is on; and when you press "Check for updates" | A request for `latest.json`, and the installer when there is a newer one. Switch the automatic check off in Settings > Updates |
| Rule lists (the `meta-rules-dat` lists, from GitHub or jsDelivr, and lists whose links you add yourself) | When the lists are updated | A plain download of the list files |
| Public DNS resolvers, a few well-known sites and speed-test files | Only when you run the network check or the speed test | Ordinary requests that tell what is reachable from your network. The result stays on the PC |
| Your Mistgate panel, block reports | Only with "Help find blocks" switched on for that subscription (off by default), after a network check, and only if the panel's owner takes such reports | Which of **your own** servers answered and which did not: protocol, the server's address and port, a verdict, the handshake time. No site names, no address of yours, no keys |
| Your Mistgate panel, debug bundle | Only when you press send, after the app has shown you every line | Version, Windows build, the last network check and the app's log, with addresses, links and names removed |

## What stays on the PC

- Device keys, server credentials and subscription links: in a store that Windows encrypts for the service's own
  account.
- The app's log: no keys, links, server addresses, names of sites or of programs. You can clear it in Settings > Privacy.
- Your routes, lists and settings.

## Third parties

The app is built from open-source parts ([THIRD_PARTY.md](THIRD_PARTY.md)); none of them is given a way to report
anything. Whoever runs your VPN server sees what any VPN server sees: that you are connected, and the traffic that
leaves through it. That is their service, not this app; ask them for their own policy.

This program will not transfer any information to other networked systems unless specifically requested by the user
or the person installing or operating it, except for the update check and the list downloads described above, both
of which can be switched off or are started by the user.
