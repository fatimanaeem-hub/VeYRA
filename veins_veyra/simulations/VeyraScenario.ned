//
// VEYRA Phase 3a scenario: Erlangen (Veins example map), SUMO cars,
// numRsus RSUs along the route, each bridged to one gateway in
// gateway_service.py, plus one roadside attacker ("eve").
//

import org.car2x.veins.nodes.RSU;
import org.car2x.veins.nodes.Scenario;

network VeyraScenario extends Scenario
{
    parameters:
        int numRsus = default(3);   // must match the number of ports given to gateway_service.py
    submodules:
        rsu[numRsus]: RSU {
            @display("i=veins/sign/yellowdiamond;is=vs");
        }
        eve: RSU {
            @display("i=device/antennatower;is=vs;i2=status/excl3");
        }
}
