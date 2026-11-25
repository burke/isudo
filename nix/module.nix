# NixOS module: programs.isudo (the setuid isudo and isudo-admin) and
# services.isudo-relay (the relay, hardened as contrib/isudo-relay.service).
#
# Pairing stays a manual step, once per machine:
#   sudo isudo-admin pair --relay https://<relay>
# It writes /etc/isudo/pairing.conf, which holds this machine's key and is
# deliberately not managed by Nix (the store is world-readable).
self:
{ config, lib, pkgs, ... }:

let
  prog = config.programs.isudo;
  relay = config.services.isudo-relay;
  apns = relay.apns;
in
{
  options = {
    programs.isudo = {
      enable = lib.mkEnableOption "isudo, sudo with approval from your phone";
      package = lib.mkOption {
        type = lib.types.package;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        defaultText = lib.literalExpression "isudo.packages.\${system}.default";
        description = "The isudo package. Its setuid path must match the wrapper this module makes.";
      };
    };

    services.isudo-relay = {
      enable = lib.mkEnableOption "the isudo relay";
      package = lib.mkOption {
        type = lib.types.package;
        default = prog.package;
        defaultText = lib.literalExpression "config.programs.isudo.package";
        description = "The package providing isudo-relay.";
      };
      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:8787";
        description = "Where the relay listens. It speaks plain HTTP: put TLS in front (tailscale serve, a reverse proxy).";
      };
      registrationTokenFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "File holding a token a host must present to pair (isudo-admin pair --registration-token). Read at start, never copied to the store.";
      };
      apns = {
        keyFile = lib.mkOption {
          type = lib.types.nullOr lib.types.path;
          default = null;
          description = "APNs auth key (.p8). Without the four apns settings the app shows requests only while open.";
        };
        keyId = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "APNs key id."; };
        teamId = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Apple developer team id."; };
        topic = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "The app's bundle id."; };
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf prog.enable {
      environment.systemPackages = [ prog.package ];
      security.wrappers.isudo = {
        source = "${prog.package}/bin/isudo";
        owner = "root";
        group = "root";
        setuid = true;
      };
    })

    (lib.mkIf relay.enable {
      assertions = [{
        assertion = let set = lib.filter (v: v != null) [ apns.keyFile apns.keyId apns.teamId apns.topic ];
                    in set == [ ] || lib.length set == 4;
        message = "services.isudo-relay.apns: set all four of keyFile, keyId, teamId and topic, or none.";
      }];

      systemd.services.isudo-relay = {
        description = "isudo relay";
        documentation = [ "https://github.com/burke/isudo" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];
        environment = {
          ISUDO_RELAY_LISTEN = relay.listen;
          ISUDO_RELAY_STATE = "/var/lib/isudo-relay/state.json";
        } // lib.optionalAttrs (apns.keyFile != null) {
          ISUDO_APNS_KEY_FILE = "%d/apns.p8";
          ISUDO_APNS_KEY_ID = apns.keyId;
          ISUDO_APNS_TEAM_ID = apns.teamId;
          ISUDO_APNS_TOPIC = apns.topic;
        };
        # The token goes in through a credential, so it never sits in the unit or the store.
        script = lib.optionalString (relay.registrationTokenFile != null) ''
          ISUDO_RELAY_REGISTRATION_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/registration-token")"
          export ISUDO_RELAY_REGISTRATION_TOKEN
        '' + ''
          exec ${relay.package}/bin/isudo-relay
        '';
        serviceConfig = {
          Restart = "on-failure";
          RestartSec = 2;
          LoadCredential =
            lib.optional (apns.keyFile != null) "apns.p8:${apns.keyFile}"
            ++ lib.optional (relay.registrationTokenFile != null) "registration-token:${relay.registrationTokenFile}";

          DynamicUser = true;
          StateDirectory = "isudo-relay";
          StateDirectoryMode = "0700";
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          # AF_UNIX and AF_NETLINK are what name resolution needs.
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
          RestrictNamespaces = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          CapabilityBoundingSet = "";
        };
      };
    })
  ];
}
