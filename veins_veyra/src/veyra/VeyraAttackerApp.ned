//
// VEYRA - roadside attacker. See VeyraAttackerApp.h.
//
package veyra;

import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple VeyraAttackerApp extends DemoBaseApplLayer
{
    parameters:
        @class(veyra::VeyraAttackerApp);
        int targetRsu = default(0);
        string intruderName = default("intruder-eve");
        int handshakeBytes = default(1125B) @unit(B);
        int readingBytes = default(150B) @unit(B);
        double intruderAt = default(5s) @unit(s);      // -1 disables an attack
        double tamperAt = default(10s) @unit(s);
        double replayFreshAt = default(12s) @unit(s);
        double replayOldAt = default(200s) @unit(s);
        double minOldAge = default(130s) @unit(s);     // replay_old waits until its capture is this old
        double retryInterval = default(1s) @unit(s);   // if nothing captured yet
}
