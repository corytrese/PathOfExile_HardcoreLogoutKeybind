# PathOfExile_HardcoreLogoutKeybind
Background service for forcing Path of Exile TCP/IP logout on keypress. Useful for hardcore players.

## Purpose
Listen for a specific keystroke globally and when it occurs, force Path of Exile game client to disconnect as quickly as possible.

## Use
1. Start Path of Exile
2. Start HardcoreLogoutKeybind
3. Login and Connect to a PoE character
4. Press the "tilde" key
5. Notice you've been rapidly logged out
6. Celebrate not being dead

## Troubleshooting

This is a simple application that could only have a few problems.

### Administrator Privs
The application needs elevated permissions to muck with Path of Exile's network connection.

### Path of Exile
The application needs to be able to find the Path of Exile Win32 process. It does this by looking for the Window title. It might not work if your Window title is not 'Path of Exile'

### Keybinding
The application supports configurable keybinding. You might have set the disconnect key to something other than ~ or might need to change the keycode used if your needs are different.

## Why?
This tool does one thing and one thing only. Other tools exist that do this in addition to other features, or aren't designed to be in compliance with GGG's ToS.
