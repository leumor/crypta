# First-party app bundle checks reference

Read for First-party app bundle checks. Commands and unlinked source paths are relative to the repository root.

## First-party app bundle checks
- Stage first-party app bundles, especially after changing `:platform-sdk-js` or
  `:platform-design-system` because Queue Manager, Publisher, Site Publisher, Profile Publisher,
  Social Inbox RC, Feed Reader, and Trust Graph Local RC copy those assets into staged static UI
  bundles:
  - `./gradlew stageFirstPartyApps`
- Run app project tests:
  - `./gradlew :apps:queue-manager:test`
  - `./gradlew :apps:publisher:test`
  - `./gradlew :apps:site-publisher:test`
  - `./gradlew :apps:profile-publisher:test`
  - `./gradlew :apps:social-inbox:test`
  - `./gradlew :apps:feed-reader:test`
  - `./gradlew :apps:trust-graph:test`
- Sign and verify staged bundles only when signing/trusted-key inputs are available:
  - `./gradlew signFirstPartyApps`
  - `./gradlew verifyFirstPartyApps`
