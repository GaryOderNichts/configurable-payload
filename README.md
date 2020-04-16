# Configurable Payload
[homebrew_launcher_installer](https://github.com/wiiu-env/homebrew_launcher_installer) and [haxchi's](https://github.com/FIX94/haxchi) config combined  

# Usage
Meant to be used with the  [payload_loader](https://github.com/wiiu-env/payload_loader).  
Put the created `payload.elf` on the sd card where the `payload_loader` can find it.
Check out the repository of the loader for further instructions.

Loads the homebrew_launcher by default.  
Can be configured with a `payload.cfg` file placed to `sd:/wiiu/payload.cfg`.  
The syntax of the config is the same as the one from haxchi.  
Here is a example that boots [mocha](https://github.com/dimok789/mocha) when button A is held:
```
    a=wiiu/apps/mocha/mocha.elf
```
If nothing is configured for a button or the config file cannot be read the homebrew_launcher is started  

## Building
In order to be able to compile this, you need to have installed
[devkitPPC](https://devkitpro.org/wiki/Getting_Started) with the following
pacman packages installed.

```
pacman -Syu devkitPPC
```

Make sure the following environment variables are set:
```
DEVKITPRO=/opt/devkitpro
DEVKITPPC=/opt/devkitpro/devkitPPC
```

The command `make` should produce a `payload.elf`, meant to be used with the
[payload_loader](https://github.com/wiiu-env/payload_loader)

# Credits

- dimok789: [original installer](https://github.com/dimok789/homebrew_launcher))
- orboditilt: port to be used with the [payload_loader](https://github.com/wiiu-env/payload_loader)
- FIX94: config for [haxchi](https://github.com/FIX94/haxchi)
