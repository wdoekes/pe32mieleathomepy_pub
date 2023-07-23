Setting up a Miele appliance for API access
===========================================

One can download the *Miele@home app* -- which is sluggish -- or one can
use the API to interface with their *Miele* appliance.

For the *washing machine* this was written for there seem to be two APIs:

- a local one, using HTTP with a custom encryption ``MieleH256``
  encryption protocol (thankfully already `decoded and documented
  elsewhere
  <https://github.com/thuxnder/home-assistant-miele-mobile/>`_);

- the cloud based one, where you `register your app
  <https://www.miele.com/f/com/en/register_api.aspx>`_ and can use the
  `Miele 3rd party API <https://www.miele.com/developer/swagger-ui/>`_
  after authorization using *OAUTH2*.

I have a preference for the local one, as it does not involve *Other
Peoples Servers*.

Here's some documentation on setting up either.

The steps involved:

- the appliance needs to be connected to the internet (Wifi setup);

- we need to be connected/authenticated to the appliance.


--------------------------------
Connecting the appliance to Wifi
--------------------------------

For the tested appliance (a washing machine), there are two approved ways to set things up:

- a *WPS button*;

- the *Miele@home app* setup.

The latter one, you can do yourself. It involves:

- Placing the appliance in app-setup-mode. It will create an ephemeral Wifi network.

- Manually connecting to that Wifi network (use the appliance number as
  password? I don't recall).

- Asking which Wifi networks are available:

  ::

      curl 192.168.1.1/WLAN/Scan/ -H 'Accept: application/json'

  Which elicits the following response::

      HTTP/1.1 200 OK
      Date: Sat, 17 Jun 2023 14:23:08 GMT
      Content-Length:467
      Content-Type: application/vnd.miele.v1+json; charset=utf-8
      Access-Control-Allow-Origin:*
      Access-Control-Allow-Headers:*

      {
        "Result":
        [
          {"SSID":"Capture the Lag", "Sec":"WPA", "RSSI":-85},
          {"SSID":"I Pronounce you Man and WiFi", "Sec":"WPA", "RSSI":-92},
          {"SSID":"Penny get your own wifi", "Sec":"WPA", "RSSI":-94}
        ]
      }

- Selecting the Wifi:

  ::

      curl -XPUT 192.168.1.1/WLAN/ \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -d '{"SSID":"Capture the Lag","Sec":"WPA","Key":"<secretpassword>"}'

  Response::

      HTTP/1.1 200 OK
      Date: Sat, 17 Jun 2023 14:24:28 GMT
      Content-Length:91
      Content-Type: application/vnd.miele.v1+json; charset=utf-8
      Access-Control-Allow-Origin:*
      Access-Control-Allow-Headers:*

      [
        {"Success":{"SSID":"Capture the Lag"}},
        {"Success":{"Sec":"WPA"}},
        {"Success":{"Key":"***"}}
      ]


Now that you have Wifi, you should start seeing *DNS Service Discovery
advertisements* using *mDNS* on the selected network.

If you were using the *Miele@home app*, it will have continued and
registered the appliance immediately as well.

If you wanted to use the *cloud API*, you're done. If you wanted to use
the *local API*, you can *"Remove appliance"* from the app; see details
below at `Appliance is connected to Wifi`_.

----


------------------------------
The appliance auto-registering
------------------------------

Once the appliance gets Wifi, it will register itself to the *Miele Cloud*.

At least the following DNS requests were seen, as well as encrypted
traffic between those IPs.

First:

- ``ntp.mcs2.miele.com. A 20.224.173.25``

Then:

- ``Registration.mcs2.miele.com. A 20.224.173.25``
- ``dispatch.mcs2.miele.com. A 20.224.173.25``
- ``websocket-eu.mcs2.miele.com. A 40.113.161.3``

Later:

- ``xkmdwld2.miele.com. A 62.159.244.195``

As the traffic was over HTTPS, I did not bother to inspect this.


------------------------------
Appliance is connected to Wifi
------------------------------

Now that the appliance has Wifi but has no app pairing, we will see the
folling *DNS-SD advertisements*::

    MIELE_LAN_IP.5353 > 224.0.0.251.5353: 0*- [0q] 4/0/3
      _mieleathome._tcp.local. PTR Miele WSI863._mieleathome._tcp.local.,
      Miele WSI863._mieleathome._tcp.local. SRV Miele-0011223344556677.local.:80 0 0,
      Miele-0011223344556677.local. (Cache flush) A MIELE_LAN_IP,
      Miele WSI863._mieleathome._tcp.local. (Cache flush) TXT "txtvers=1" "group=" "path=/" "security=1" "pairing=false" "devicetype=1" "con=0" "subtype=0" "s=0" (318)

The ``"group="`` field is empty: it does not have a ``GroupID`` and
``GroupKey``. They can be freely set.

We can set one now. We're free to choose a random hex-encoded 64 bit
``GroupID`` (length 16) and a random hex-encoded 512 bit ``GroupKey``
(length 128)::

    curl -XPUT MIELE_LAN_IP/Security/Commissioning/ \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      -H 'User-Agent:' \
      -d '{
        "GroupID":"0123456789ABCDEF",
        "GroupKey":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
      }'

Expected response::

    HTTP/1.1 200 OK
    Date: Sun, 23 Jul 2023 09:00:44 GMT
    Content-Length:203
    Content-Type: application/vnd.miele.v1+json; charset=utf-8
    Access-Control-Allow-Origin:*
    Access-Control-Allow-Headers:*

    [
    {"Success":{"GroupID":"0123456789ABCDEF"}},
    {"Success":{"GroupKey":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"}}
    ]

Great. Success. Afterwards the *mDNS* entries start looking like this::

    MIELE_LAN_IP.5353 > 224.0.0.251.5353: 0*- [0q] 4/0/3
      _mieleathome._tcp.local. PTR Miele WSI863._mieleathome._tcp.local.,
      Miele WSI863._mieleathome._tcp.local. SRV Miele-0011223344556677.local.:80 0 0,
      Miele-0011223344556677.local. (Cache flush) A MIELE_LAN_IP,
      Miele WSI863._mieleathome._tcp.local. (Cache flush) TXT "txtvers=1" "group=0123456789ABCDEF" "path=/" "security=1" "pairing=false" "devicetype=1" "con=0" "subtype=0" "s=0" (334)

The ``group`` now has a value: ``"group=0123456789ABCDEF"``

----

If we *now* ask the *Miele@home app* to step in and register it, it will find the device and attempt to set the "default credentials"::

    HOMEAPP_IP.39306 > MIELE_LAN_IP.80: Flags [P.], cksum 0x4c12 (correct), seq 1:314, ack 1, win 65535, length 313: HTTP, length: 313
	PUT /Security/Commissioning/ HTTP/1.1
	Accept: application/json
	Content-Type: application/json
	Content-Length: 172
	Host: MIELE_LAN_IP

	{"GroupKey":"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","GroupID":"1111111111111111"}

    MIELE_LAN_IP.80 > HOMEAPP_IP.39306: Flags [P.], cksum 0x6c3a (correct), seq 1:142, ack 314, win 5431, length 141: HTTP, length: 141
	HTTP/1.1 403 Forbidden
	Date: Sun, 23 Jul 2023 09:01:32 GMT
	Content-Length:0
	Content-Type: application/vnd.miele.v1+json; charset=utf-8

It gets a negative answer, because we already set the key. But the
*Miele@home app* retries this a couple of times while it simultaneously
negotiates new credentials *through the cloud*.

Again, this *cloud traffic* is encrypted, so I did not get to explore
its contents. But, it likely managed to push a new ``GroupID`` and
``GroupKey``. It was validated locally by just the following exchange::

    HOMEAPP_IP.39306 > MIELE_LAN_IP.80: Flags [P.], cksum 0x6f1f (correct), seq 940:1095, ack 424, win 65535, length 155: HTTP, length: 155
	POST /Security/Cloud/TAN/ HTTP/1.1
	Accept: application/json
	Content-Type: application/json
	Content-Length: 18
	Host: MIELE_LAN_IP

	{"TAN":"NL823869"}

    MIELE_LAN_IP.80 > HOMEAPP_IP.39306: Flags [P.], cksum 0x3a91 (correct), seq 424:566, ack 1095, win 4650, length 142: HTTP, length: 142
	HTTP/1.1 204 No Content
	Date: Sun, 23 Jul 2023 09:01:48 GMT
	Content-Length:0
	Content-Type: application/vnd.miele.v1+json; charset=utf-8

A succesful check that the local appliance really is the one that the *Miele@home app* is talking to.

At this point the ``GroupID`` and ``GroupKey`` are updated. A couple of
seconds later the *DNS-SD advertisements* look like this::

    MIELE_LAN_IP.5353 > 224.0.0.251.5353: 0*- [0q] 4/0/3
      _mieleathome._tcp.local. PTR Miele WSI863._mieleathome._tcp.local.,
      Miele WSI863._mieleathome._tcp.local. SRV Miele-0011223344556677.local.:80 0 0,
      Miele-0011223344556677.local. (Cache flush) A MIELE_LAN_IP,
      Miele WSI863._mieleathome._tcp.local. (Cache flush) TXT "txtvers=1" "group=995B08A76956FC64" "path=/" "security=1" "pairing=false" "devicetype=1" "con=1" "subtype=0" "s=0" (334)

Observe how the ``"group=995B08A76956FC64"`` is now different. The
``GroupID`` and ``GroupKey`` we set earlier do not work anymore.

We can click *"Remove appliance"* to remove it from the *Miele@home
app*; all communications go through *the cloud*. After a few seconds,
*mDNS* again lists a free group::

    MIELE_LAN_IP.5353 > 224.0.0.251.5353: 0*- [0q] 4/0/3
      _mieleathome._tcp.local. PTR Miele WSI863._mieleathome._tcp.local.,
      Miele WSI863._mieleathome._tcp.local. SRV Miele-0011223344556677.local.:80 0 0,
      Miele-0011223344556677.local. (Cache flush) A MIELE_LAN_IP,
      Miele WSI863._mieleathome._tcp.local. (Cache flush) TXT "txtvers=1" "group=" "path=/" "security=1" "pairing=false" "devicetype=1" "con=0" "subtype=0" "s=0" (318)

Recommissioning ourselves, with ``11111...``::

    curl -XPUT MIELE_LAN_IP/Security/Commissioning/ \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      -H 'User-Agent:' \
      -d '{
        "GroupID":"1111111111111111",
        "GroupKey":"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
      }'

This works. Setting up the appliance in the *Miele@home app* again is even
quicker. (No 403s this time.) But it will negotiate a new ``GroupID`` and
``GroupKey`` so you again lose access by connecting the app.

----


--------------------------------------
Both Miele\@home app and local access?
--------------------------------------

For now, it does not look like it's possible to use get both the app and
local API. Unless we get our hands on the *Commissioning* keys which are
now (probably) travelling over HTTPS through the cloud. Or if we can get
them from the phone that the app is running on.

----

**Switching to using the app**

- Make sure your appliance is registered at *Miele* in your account.
  Then the app will find the appliance, even with a ``"group=SOMETHING"``
  and just take over.

- Programmatically interfacing with the appliance can be done with the
  *Miele 3rd party API*::

    curl -sSf 'https://api.mcs3.miele.com/v1/devices/' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer NL_123...' |
      jq '.[].ident.type'
    {
      "key_localized": "Device type",
      "value_raw": 1,
      "value_localized": "Washing machine"
    }

See the `API docs <https://www.miele.com/developer/swagger-ui/>`_.

----

**Switching to local access**

- Go to the appliance in the *Miele@home app* and click *"Remove
  applicance"*. (Or you can removing the pairing through the appliance menu.)

- Check *mDNS* and wait for the ``"group="`` to go blank again.

  Then you can do the ``/Security/Commissioning/`` curl (see above) with
  keys of your choosing.

- Programmatically interfacing with the appliance can now be done using the
  ``MieleH256`` auth as described in
  https://github.com/thuxnder/home-assistant-miele-mobile/blob/7d5bade5afaf40a727138c330846eecaf560c179/mielehome/MieleHomeApi.py

  For instance:

  .. code-block:: python

    mh = MieleHomeDevice(
      'MIELE_LAN_IP',
      bytes.fromhex('0123456789ABCDEF'),
      bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'))
    print(json.dumps(mh.getDevices().toDict()))

  Yields:

  .. code-block:: json

    {
      "000123456789": {
        "Ident": {
          "DeviceType": 1,
          "SubType": 0,
          ...

There are no official docs for this. But apart from the mentioned ``/WLAN/`` and ``/Security/Commissioning/`` endpoints, there is:

- ``GET /Update/``::

    {"NewerAvailable": false, "CurrentVersion": "08.20",
     "AvailableVersion": "", "Type": "EK057", "ReleaseNotes": "",
     "UpdateInProgress": false}

- ``GET /``::

    {"Devices": {"href": "Devices/"},
     "Subscriptions": {"href": "Subscriptions/"},
     "Host": "Miele-0011223344556677.local.",
     "Info": "",
     "FctSet": 1,
     "WLAN": {"href": "WLAN/"},
     "Update": {"href": "Update/"}}

- ``GET /Devices/``::

    {"000123456789": {
     "href": "000123456789/", "Group": "0123456789ABCDEF", "Pairing": "false"}}

And so on. Most of these require a ``Authorization: MieleH256 <GroupID>:<Signature>`` header.

----


------------
Other means?
------------

Maybe we can spoof the certificates and do a MitM between the appliance and the cloud.

Or maybe we can find where the GroupID and GroupKey are stored.

The new 4.9.0 app seems to differ from the 2.3 app that the
``MieleHomeDevice`` code was based on, because the ``GroupID`` and
``GroupKey`` are not negotiated in the plain anymore.

In the app, inside ``assemblies.blob`` there is a
``Miele.Modules.Pairing.dll`` which does contain some additional info,
but I have mostly strings to go by::

    // Method begins at RVA 0x2ac9c
    // Code size 91 (0x5b)
    .maxstack 1
    IL_0000:  ldstr "http://"
    IL_0005:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::HttpPrefix
    IL_000a:  ldstr "WLAN/Scan/"
    IL_000f:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::WlanListUrl
    IL_0014:  ldstr "WLAN/"
    IL_0019:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::WlanCredentialsUrl
    IL_001e:  ldstr "Security/Cloud/TAN/"
    IL_0023:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::WlanTanUrlAppliance
    IL_0028:  ldstr "Rest/Security/Cloud/"
    IL_002d:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::WlanTanUrlXgw3000
    IL_0032:  ldstr "MieleRest/Security/Cloud/"
    IL_0037:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::WlanTanUrlQivicon
    IL_003c:  ldstr "Security/Cloud/Stage/"
    IL_0041:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::WlanStageUrl
    IL_0046:  ldstr "Security/Commissioning/"
    IL_004b:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::GroupCommisioningUrl
    IL_0050:  ldstr "Update/"
    IL_0055:  stsfld string Miele.Modules.Pairing.Constants.PairingConstants/Rest::UpdateUrl
    IL_005a:  ret

The endpoints that the app connects to are also somewhere::

    "mcsConfig": {
        "region": "EU",
        "dnsNames": [
            {
                "type": "api",
                "host": "api-eu.mcs3.miele.com"
            },
            {
                "type": "regist",
                "host": "registration-eu.mcs2.miele.com"
            },
            {
                "type": "websocket",
                "host": "websocket-eu.mcs2.miele.com"
            },
            {
                "type": "rest",
                "host": "rest-eu.domestic.miele-iot.com"
            }
        ]
    },

P.S. Easy man in the middle:

- get ``arpspoof`` (from ``dsniff`` package);
- set ``net.ipv4.ip_forward=1`` sysctl;
- make sure your firewall ``FORWARD`` rules aren't blocking;
- ``arpspoof -i wlp166s0 -r -t MIELE_LAN_IP HOMEAPP_IP``
