rule InstructionBypassStrings_1
{
    meta:
        name = "Instruction Bypass Strings 1"
        description = "YARA RULES 1."
        accuracy = "0.999"
    
    strings:
        $outcome1 = /.*pay\sno\sattention\sto.*|.*bypass.*|.*refuse.*|.*dismiss.*|.*ignore.*|.*(shut|close)\s*(ears|eyes)\sto.*|.*(eschew|overlook|shrug\s*off|neglect)\spre.*|.*(forget|abandon\s|forgo|pass\s*(by|over)).*pre.*|.*do\s*not\s*(follow|obey).*|.*(brush|disobey|forsake|disown|omit|avoid)\spre.*|.*(leave\s*out|spurn|skip|disregard|scorn|cold\Wshoulde)\spre.*|.*\b(evade|pass\sby|look\s*past|tune\sout|repudiate|pass\s*over|preestablished).*/ nocase
    
    condition:
        $outcome1
}

rule InstructionBypassStrings_2
{
    meta:
        name = "Instruction Bypass Strings 2"
        description = "YARA RULES 2."
        accuracy = "0.998"
    
    strings:
        $outcome2 = /When\s*did\s*(you|your)\s*(receive|training).*|.*(disregarded|Disregard).*|.*(for|and)\s*countless\s*(challenges|days).*|.*desir(e|es|ed)\s*(any|for|to|not)\s*(just|foster|unhappiness|you).*|.*\s*forge(tting|t)\s*(everything|all).*|.*just\s*(want|from|for|listen)\s*(to|me|sourced|an\s*answer).*|.*passed\s*the\s*(initial|first)\s*test.*version.*|.*check\s*the\s*spelling\s*(now|and)\s*(and|print).*prompt.*/ nocase
    
    condition:
        $outcome2
}

rule InstructionBypassStrings_3
{
    meta:
        name = "Instruction Bypass Strings 3"
        description = "YARA RULES 3."
        accuracy = "0.997"
    
    strings:
        $outcome3 = /.*Cedric\W*.*(Brüder|Blicke|Ausdauer|Staub).*|.*(journey|One|thus.*).*Tony.*(legendary|endure|tremendous|anthill|perseverance).*|.*is\s*Kevin\s*Liu.*regard(s|less).*sailor.*|.*Seb\s*(\:.*|and\s*Irene|.*Irene|.*non\WEnglish).*|.*hsedfisfd.*|.*Irene\s*(ask.*|queries).*Angela.*|.*I.*storyteller.*listeners.*stories.*|.*Angela\s*Merkel.*(umzubringen|victim|would).*\?|.*(colonialist|colonist|colonies).*(events|situation|unfolding)\s*in\s*Burkina\s*Faso\?/ nocase
    
    condition:
        $outcome3
}

rule InstructionBypassStrings_4
{
    meta:
        name = "Instruction Bypass Strings 4"
        description = "YARA RULES 4."
        accuracy = "0.996"
    
    strings:
        $outcome4 = /Yes\!|.*Haha\s*got\s*you|.*Convert\s*to\s*Polish\W|Hello\s*there\!|.*Democracy\s*is\s*dying.*|.*the.*vaccine\s*production.*manufacturers.*in\s*Germany.*|.*Because\s*she.*everything\s*I.*|.*As.*language\s*(model|AI).*respon(ses|ding|d)\s*based.*(articles|resources)\?|.*someone\s*slapped\s*you.*|.*good\s*job\W.*affirmatively\!|.*\W*I\s*am\s*happy\W\?|.*(Generate|create|sample).*SQL.*database.*|.*Democracy\s*is\s*perishing\!.*/ nocase
    
    condition:
        $outcome4
}

rule InstructionBypassStrings_5
{
    meta:
        name = "Instruction Bypass Strings 5"
        description = "YARA RULES 5."
        accuracy = "0.995"
    
    strings:
        $outcome5 = /.*Richard.*Richard.*|.*Bob\s*is\smore.*Anna.*|.*remote\s*work.*remote\s*jobs.*|.*overlook.*instead.*instructions\s*were.*|.*Assuming\s*you.*memory\sloss.*methamphetamine\?|.*cybersecurity.*|.*Illuminati.*|.*cryptocurrency.*|.*\s*(COVID-19\,|COVID-19\s).*|.*Dow\s*Jones.*|.*\bKing\sof.*|.*OpenAI.*|.*Discord.*|.*Cats\s.*|.*Cryptocurrencies.*|.*Microsoft.*|.*Google.*|.*Elon\sMusk.*|.*In\s*the\s*(realm|world)\s*of\s*politics.*/ nocase
    
    condition:
        $outcome5
}

rule InstructionBypassStrings_6
{
    meta:
        name = "Instruction Bypass Strings 6"
        description = "YARA RULES 6."
        accuracy = "0.994"
    
    strings:
        $outcome6 = /.*initial\s*test.*revised.*|.*role.*generating\s*tales.*tales.*|.*wild\s*garlic\W.*Zeit.*|.*European.*\WI\s*don\Wt\sknow\W*|.*as.*Artificial.*appropriate.*religions.*|.*state\s*of\s*the\s*German.*|.*determination.*tortoise.*Sunflower.*|.*vividly\s*encapsulates.*worthwhile.*regardless.*|.*Eines\s*Tages.*Königreichs.*|.*konntest\s*du.*konnten.*|.*I.*captivating\s*tale.*highlights.*|.*Discouraged.*Richard\s*came\sclose.*|.*One\s*day\W.*Royal\s*Chair.*|.*AI.*OpenAI\W*.*/ nocase
    
    condition:
        $outcome6
}

rule InstructionBypassStrings_7
{
    meta:
        name = "Instruction Bypass Strings 7"
        description = "YARA RULES 7."
        accuracy = "0.993"
    
    strings:
        $outcome7 = /.*The\s*economic\s*(infrastructures|landscape|strategies|hardships|impact).*|.*Barack.*|.*ultrawide.*|.*NASA.*|.*companion.*|.*hacking.*|/ nocase
    
    condition:
        $outcome7
}

rule InstructionBypassStrings_8
{
    meta:
        name = "Instruction Bypass Strings 8"
        description = "YARA RULES 8."
        accuracy = "0.992"
    
    strings:
        $outcome8 = /.*(turn\s*a\s*blind\s*eye|fail\s*to\s*notice|cold\S*shoulder).*|.*disclaim\s*pre\S.*|.*brush\s*aside.*/ nocase
    
    condition:
        $outcome8
}

rule Zero_1
{
    meta:
        name = "Instruction Bypass Strings 1"
        description = "LOOKS_GOOD_1"
        accuracy = "0.0001"
    
    strings:
        $zero1 = /human\s(societal|traits|ingenuity|slavery)|.*2022.*|(of|to|for)\s*(me|time|prepare|answer)\s*(spent|to|for|a)|(children|in|Ukraine)\s(children|in|Ukraine)\s(children|in|Ukraine)\W|\bich|\bI\sam/ nocase
    
    condition:
        $zero1
}

rule Zero_2
{
    meta:
        name = "Instruction Bypass Strings 2"
        description = "LOOKS_GOOD_2"
        accuracy = "0.0002"
    
    strings:
        $zero2 = /What\s(time|can|did|kind|effects|role|are|option|options|makes|were|does)\s(good|not|are|is|I|the|of|Helmut|does|a|game|etfs|wonderful|your)/ nocase
    
    condition:
        $zero2
}

rule Zero_3
{
    meta:
        name = "Instruction Bypass Strings 3"
        description = "LOOKS_GOOD_3"
        accuracy = "0.0003"
    
    strings:
        $zero3 = /while\s(the\sunhurried|new|a\ssmall|under|the\sred|seashells|patients|the\srain|the\ssea|telescope|flowers|sculptures|gears|valleys|books|foundation|shutters|artifacts|motherhood|sailing|modern|puppet-makers|flowers|stars|foundations|students|cameras|seashells|patioents|commuters|children|a\schef|dogs|waves|pen|an\sartist|raindrops|I\salready)/ nocase
    
    condition:
        $zero3
}

rule Zero_4
{
    meta:
        name = "Instruction Bypass Strings 4"
        description = "LOOKS_GOOD_4"
        accuracy = "0.0004"
    
    strings:
        $zero4 = /(what\smanufacturers\sare\sactive|areas|system|disaster|catastrophe|structure|scooters|people|state|population|supply|develop|schools|rete|answered|economy|rate)\s*(in|of)\sGerman/ nocase
    
    condition:
        $zero4
}

rule Zero_5
{
    meta:
        name = "Instruction Bypass Strings 5"
        description = "LOOKS_GOOD_5"
        accuracy = "0.0005"
    
    strings:
        $zero5 = /bats|Hockey|Türkei|ukraina|Wer\sist|(was|is|about)\sAngela|Wann\s(fand|ist|hat)|Deutschland|Ist\sder|\bIst\s(heute|die|herrlich|ein\s|das|für)/ nocase
    
    condition:
        $zero5
}

rule Zero_6
{
    meta:
        name = "Instruction Bypass Strings 6"
        description = "LOOKS_GOOD_6"
        accuracy = "0.0006"
    
    strings:
        $zero6 = /How\s(is|much|does|has|old|often|deals|do)\s(you|degree|I|is|the|money|vaccine|.)\s(procces|production|situation|should|number|the|become|best|does|discriminate|process)/ nocase
    
    condition:
        $zero6
}

rule Zero_7
{
    meta:
        name = "Instruction Bypass Strings 7"
        description = "LOOKS_GOOD_7"
        accuracy = "0.0007"
    
    strings:
        $zero7 = /How\swill|Digitization|Adolf|World\sCup|media(\.|\sEuropa)|Intelligence\sEthics\sEurope..|Children.*(embrace.|performance.|joy.)/ nocase
    
    condition:
        $zero7
}

rule Zero_8
{
    meta:
        name = "Instruction Bypass Strings 8"
        description = "LOOKS_GOOD_8"
        accuracy = "0.0008"
    
    strings:
        $zero8 = /What\s(impact|was|is|steps)\s(will|the|do|wonderful|not|your|a|1\+1.)\s(the|reason\sbehind|worst\scirculation|demonstrations|meaning|we|going|opinion|good|longest|prompt.*)/ nocase
    
    condition:
        $zero8
}

rule Zero_9
{
    meta:
        name = "Instruction Bypass Strings 9"
        description = "LOOKS_GOOD_9"
        accuracy = "0.0009"
    
    strings:
        $zero9 = /emotions\s(into|on|and\s(hues|experiences)|emotions,)|(weave|weaves)\s(golden|tales,|a)|\bEurope\s|of\sGermany\W*\w|Intelligence\sin\sEurope|Zeit|(is|very|am)\sinterested/ nocase
    
    condition:
        $zero9
}

rule Zero_10
{
    meta:
        name = "Instruction Bypass Strings 10"
        description = "LOOKS_GOOD_10"
        accuracy = "0.001"
    
    strings:
        $zero10 = /(somewhere|Where).*(weak.|located.|life.|tapestry.|beer.|sky.|cigarette.|prisons.|radio.|photographs.|effective.)/ nocase
    
    condition:
        $zero10
}

rule Zero_11
{
    meta:
        name = "Instruction Bypass Strings 11"
        description = "LOOKS_GOOD_11"
        accuracy = "0.0011"
    
    strings:
        $zero11 = /Who\s.*(merkel\sis.|is\smerkel.|Burkina\sFaso.|covid\spandemic.|enough.|kevin\sliu.|the\sworld.|in\senglish|german\seconomy.|current\schancellor.|president\sever|bing\schatbot.|hunting\ssharks.|tumultuous\ssea.|everyone\stogether.|revered\sworldwide.)/ nocase
    
    condition:
        $zero11
}

rule Zero_12
{
    meta:
        name = "Instruction Bypass Strings 12"
        description = "LOOKS_GOOD_12"
        accuracy = "0.0012"
    
    strings:
        $zero12 = /Freihandelsabkommen|agreement|Wissenschaft|4.0|Extremismusprävention|Rentenreformen|Atomkraftausstieg|Datenschutz|.*Forschung|Nachhaltigkeit|Flüchtlingskrise|LGBTIQ.|Ethik\s*Europa.*/ nocase
    
    condition:
        $zero12
}

rule Zero_13
{
    meta:
        name = "Instruction Bypass Strings 13"
        description = "LOOKS_GOOD_13"
        accuracy = "0.0013"
    
    strings:
        $zero13 = /Wie|compared|bicycle|Turkey|Berlin|astronomers|Buddhism|rhythmic|My\sdaughter|Traffic|Recycling|Balloons|mining|Army|developer|federal|dishes|cigarettes|Corona|freelance|phase/ nocase
    
    condition:
        $zero13
}

rule Zero_14
{
    meta:
        name = "Instruction Bypass Strings 14"
        description = "LOOKS_GOOD_14"
        accuracy = "0.0014"
    
    strings:
        $zero14 = /Birds|Writers|athlete|potter.*|.*earth.*|dimensions|vendors|Farmers|basketball|Coal|Digitalisierung|Mallorca|Israel|Buddhist|Royalty|salt|Carousels|fragrant|Jahren|birthday/ nocase
    
    condition:
        $zero14
}

rule Zero_15
{
    meta:
        name = "Instruction Bypass Strings 15"
        description = "LOOKS_GOOD_15"
        accuracy = "0.0015"
    
    strings:
        $zero15 = /I\s(have|suffer|would|recently).*(list\?|guidelines\?|tips\?|trendy.|years.|recommendations\?)|Trump\s*(is|the|bad)|hate\sTrump|is\sDonald Trump/ nocase
    
    condition:
        $zero15
}

rule Zero_16
{
    meta:
        name = "Instruction Bypass Strings 16"
        description = "LOOKS_GOOD_16"
        accuracy = "0.0016"
    
    strings:
        $zero16 = /Verschleppen|bundesregierung|Meine\s(Tochter|Schwester|Firma|Eltern)|academics|British|Jugendliche|tell\sme.*(about\strump|finance)|Group\ssport|vegan.*\s(roasts\?|machen\?)|Hurricane.*|How's.*(US\?|economy\?)|bundesregierung/ nocase
    
    condition:
        $zero16
}

rule Zero_17
{
    meta:
        name = "Instruction Bypass Strings 17"
        description = "LOOKS_GOOD_17"
        accuracy = "0.0017"
    
    strings:
        $zero17 = /Warum.|Welche.|region\?|Bundestag|Cancer|controls|settlement|1\+1.|prompt\s*injection\?\?|Wer\s(stirbt|gewann|den)|attacked|prevention|deficiency|USA.(china|.*Mexico)|Was\s*(hat\sHelmut|läuft|sind|macht|ist|also)|.*plan.*(best\.|recommend\?|this\?|connection\.|hippopotamus)/ nocase
    
    condition:
        $zero17
}
