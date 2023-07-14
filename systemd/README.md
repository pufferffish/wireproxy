# Running wireproxy with systemd

If you're on a systemd-based distro, you'll most likely want to run Wireproxy as a systemd unit.

The provided systemd unit assumes you have the wireproxy executable installed on `/opt/wireproxy/wireproxy` and a configuration file stored at `/etc/wireproxy.conf`. These paths can be customized by editing the unit file.

# Setting up the unit

1. Copy the `wireproxy.service` file from this directory to `/etc/systemd/system/`, or use the following cURL command to download it:
   ```bash
   sudo curl https://raw.githubusercontent.com/pufferffish/wireproxy/master/systemd/wireproxy.service > /etc/systemd/system/wireproxy.service
   ```

2. If necessary, customize the unit.

   Edit the parts with `ExecStartPre=` and `ExecStart=` to point to the executable and the configuration file. For example, if wireproxy is installed on `/usr/bin` and the configuration file is located in `/opt/myfiles/wireproxy.conf` do the following change:
   ```service
   ExecStartPre=/usr/bin/wireproxy -n -c /opt/myfiles/wireproxy.conf
   ExecStart=/usr/bin/wireproxy -c /opt/myfiles/wireproxy.conf
   ```
   #### 2.2 Drop root privileges (optional, but recommended)
   Without any modifications, this Wireproxy service will run as root. You might want to drop those privileges. One way to do this is to simply create a system account for Wireproxy (or just use your own user account to run it instead).
   ```bash
   sudo useradd --comment "Wireproxy tunnel" --system wireproxy
   ```
   Then uncomment these lines from the wireproxy.service:
   ```service
   #User=wireproxy
   #Group=wireproxy
   ```
   Caveats:
     1) Make sure `wireproxy` user can read the wireproxy configuration file.
     2) Also note that unprivileged user cannot bind to ports below 1024 by default.

4. Reload systemd and enable the unit.
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now wireproxy.service
   ```

5. Make sure it's working correctly.

   Finally, check out the unit status to confirm `wireproxy.service` has started without problems. You can use commands like `systemctl status wireproxy.service` and/or `sudo journalctl -u wireproxy.service`.

# Additional notes

If you want to disable the extensive logging that's done by Wireproxy, simply add `-s` parameter to `ExecStart=`. This will enable the silent mode that was implemented with [pull/67](https://github.com/pufferffish/wireproxy/pull/67).
