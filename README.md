# haibi-chan
Continuous deployment specialist

## Motivation
配備ちゃん (haibi-chan) is a continuous deployment utility microservice for
PeraPera Quest.

When a new version of PeraPera Quest is merged into the code repository for
PeraPera Quest on GitHub, there are Continuous Integration (CI) workflows
that fire up to build the game. Those workflows publish a "Package" to the
GitHub Container Registry (ghcr.io), making that version of the game
available for download and deployment.

In a GitHub repository, one can configure Webhooks. This tells GitHub that
when certain events happen (like publishing a new `package`), that it should
send a POST request to the configured URL to report that the event happened.

Haibi-chan listens for these webhook calls from GitHub. When it receives the
webhook, it will instruct the server to download and publish the latest
version of the game, making it available on the web.

It also has a Discord integration. This time, Haibi-chan is the one making a
call to a webhook. By calling the webhook provided by Discord, Haibi-chan can
send a message to the configured channel on Discord. Haibi-chan does this to
inform everybody on Discord that a new version is available to play.

## License
haibi-chan
Copyright 2025 Patrick Meade.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
