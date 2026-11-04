# How to Run

## Requirements

- Python 3.9 or newer
- `pip`

## Install

```bash
pip install -r requirements.txt
```

## Provision the project

This creates the controller, device, and user configuration files.

```bash
python provision.py
```

## Run the demo

The demo runs normal commands and the attack scenarios automatically.

```bash
python demo.py
```

## Run the tests

```bash
python -m unittest discover -s tests -t . -v
```

## Run the live smoke test

This starts the controller and devices in separate processes and checks the command-line clients.

```bash
python scripts/live_smoke.py
```

## Run the formal verification

Install ProVerif separately and make sure `proverif` is available on `PATH`.

```bash
python formal/run_formal.py
```

## Run the components manually

Start the controller first:

```bash
python controller.py --pairing-console
```

In separate terminals, start the devices:

```bash
python device.py config/device_light1.json
python device.py config/device_door1.json
```

Then start a user:

```bash
python user.py config/user_hari.json
```

The user application asks for the configured PIN. Commands can also be supplied directly:

```bash
python user.py config/user_hari.json --cmd light1:TURN_ON --cmd light1:STATUS
python user.py config/user_hari.json --cmd door1:UNLOCK
```

## Clean up

Stop running processes with `Ctrl+C`. To create a fresh setup:

```bash
rm -rf config audit.log notifications.log
python provision.py
```
