// SPDX-License-Identifier: LGPL-2.1
// Copyright (C) 2020-2021, Intel Corporation. All rights reserved.
/*
	* SPD decoding portion of this code is copied from spd-decode.c
	* spd-vendor.c, source of this code can be located at:
	* https://github.com/lpereira/hardinfo/blob/master/modules/devices/spd-decode.c
	* https://github.com/lpereira/hardinfo/blame/master/modules/devices/spd-vendors.c
*/
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <uuid/uuid.h>
#include <ccan/list/list.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <ccan/array_size/array_size.h>
#include <ccan/short_types/short_types.h>

#include <util/log.h>
#include <util/sysfs.h>
#include <util/bitmap.h>
#include <cxl/cxl_mem.h>
#include <cxl/libcxl.h>
#include "private.h"

const char *DEVICE_ERRORS[23] = {
	"Success: The command completed successfully.",
	"Background Command Started: The background command started successfully. Refer to the Background Command Status register to retrieve the command result.",
	"Invalid Input: A command input was invalid.",
	"Unsupported: The command is not supported.",
	"Internal Error: The command was not completed due to an internal device error.",
	"Retry Required: The command was not completed due to a temporary error. An optional single retry may resolve the issue.",
	"Busy: The device is currently busy processing a background operation. Wait until background command completes and then retry the command.",
	"Media Disabled: The command could not be completed because it requires media access and media is disabled.",
	"FW Transfer in Progress: Only one FW package can be transferred at a time. Complete the current FW package transfer before starting a new one.",
	"FW Transfer Out of Order: The FW package transfer was aborted because the FW package content was transferred out of order.",
	"FW Authentication Failed: The FW package was not saved to the device because the FW package authentication failed.",
	"Invalid Slot: The FW slot specified is not supported or not valid for the requested operation.",
	"Activation Failed, FW Rolled Back: The new FW failed to activate and rolled back to the previous active FW.",
	"Activation Failed, Cold Reset Required: The new FW failed to activate. A cold reset is required.",
	"Invalid Handle: One or more Event Record Handles were invalid.",
	"Invalid Physical Address: The physical address specified is invalid.",
	"Inject Poison Limit Reached: The devices limit on allowed poison injection has been reached. Clear injected poison requests before attempting to inject more.",
	"Permanent Media Failure: The device could not clear poison due to a permanent issue with the media.",
	"Aborted: The background command was aborted by the device.",
	"Invalid Security State: The command is not valid in the current security state.",
	"Incorrect Passphrase: The passphrase does not match the currently set passphrase.",
	"Unsupported Mailbox: The command is not supported on the mailbox it was issued on. Used to indicate an unsupported command issued on the secondary mailbox.",
	"Invalid Payload Length: The payload length specified in the Command Register is not valid. The device is required to perform this check prior to processing any command defined in this specification.",
};

#define VENDORS_BANKS 8
#define VENDORS_ITEMS 128
const char *vendors[VENDORS_BANKS][VENDORS_ITEMS] =
{
{"AMD", "AMI", "Fairchild", "Fujitsu",
 "GTE", "Harris", "Hitachi", "Inmos",
 "Intel", "I.T.T.", "Intersil", "Monolithic Memories",
 "Mostek", "Freescale (former Motorola)", "National", "NEC",
 "RCA", "Raytheon", "Conexant (Rockwell)", "Seeq",
 "NXP (former Signetics, Philips Semi.)", "Synertek", "Texas Instruments", "Toshiba",
 "Xicor", "Zilog", "Eurotechnique", "Mitsubishi",
 "Lucent (AT&T)", "Exel", "Atmel", "SGS/Thomson",
 "Lattice Semi.", "NCR", "Wafer Scale Integration", "IBM",
 "Tristar", "Visic", "Intl. CMOS Technology", "SSSI",
 "MicrochipTechnology", "Ricoh Ltd.", "VLSI", "Micron Technology",
 "SK Hynix (former Hyundai Electronics)", "OKI Semiconductor", "ACTEL", "Sharp",
 "Catalyst", "Panasonic", "IDT", "Cypress",
 "DEC", "LSI Logic", "Zarlink (former Plessey)", "UTMC",
 "Thinking Machine", "Thomson CSF", "Integrated CMOS (Vertex)", "Honeywell",
 "Tektronix", "Oracle Corporation (former Sun Microsystems)", "Silicon Storage Technology", "ProMos/Mosel Vitelic",
 "Infineon (former Siemens)", "Macronix", "Xerox", "Plus Logic",
 "SunDisk", "Elan Circuit Tech.", "European Silicon Str.", "Apple Computer",
 "Xilinx", "Compaq", "Protocol Engines", "SCI",
 "Seiko Instruments", "Samsung", "I3 Design System", "Klic",
 "Crosspoint Solutions", "Alliance Semiconductor", "Tandem", "Hewlett-Packard",
 "Integrated Silicon Solutions", "Brooktree", "New Media", "MHS Electronic",
 "Performance Semi.", "Winbond Electronic", "Kawasaki Steel", "Bright Micro",
 "TECMAR", "Exar", "PCMCIA", "LG Semi (former Goldstar)",
 "Northern Telecom", "Sanyo", "Array Microsystems", "Crystal Semiconductor",
 "Analog Devices", "PMC-Sierra", "Asparix", "Convex Computer",
 "Quality Semiconductor", "Nimbus Technology", "Transwitch", "Micronas (ITT Intermetall)",
 "Cannon", "Altera", "NEXCOM", "QUALCOMM",
 "Sony", "Cray Research", "AMS(Austria Micro)", "Vitesse",
 "Aster Electronics", "Bay Networks (Synoptic)", "Zentrum or ZMD", "TRW",
 "Thesys", "Solbourne Computer", "Allied-Signal", "Dialog",
 "Media Vision", "Numonyx Corporation (former Level One Communication)"},
{"Cirrus Logic", "National Instruments", "ILC Data Device", "Alcatel Mietec",
 "Micro Linear", "Univ. of NC", "JTAG Technologies", "BAE Systems",
 "Nchip", "Galileo Tech", "Bestlink Systems", "Graychip",
 "GENNUM", "VideoLogic", "Robert Bosch", "Chip Express",
 "DATARAM", "United Microelec Corp.", "TCSI", "Smart Modular",
 "Hughes Aircraft", "Lanstar Semiconductor", "Qlogic", "Kingston",
 "Music Semi", "Ericsson Components", "SpaSE", "Eon Silicon Devices",
 "Programmable Micro Corp", "DoD", "Integ. Memories Tech.", "Corollary Inc.",
 "Dallas Semiconductor", "Omnivision", "EIV(Switzerland)", "Novatel Wireless",
 "Zarlink (former Mitel)", "Clearpoint", "Cabletron", "STEC (former Silicon Technology)",
 "Vanguard", "Hagiwara Sys-Com", "Vantis", "Celestica",
 "Century", "Hal Computers", "Rohm Company Ltd.", "Juniper Networks",
 "Libit Signal Processing", "Mushkin Enhanced Memory", "Tundra Semiconductor", "Adaptec Inc.",
 "LightSpeed Semi.", "ZSP Corp.", "AMIC Technology", "Adobe Systems",
 "Dynachip", "PNY Electronics", "Newport Digital", "MMC Networks",
 "T Square", "Seiko Epson", "Broadcom", "Viking Components",
 "V3 Semiconductor", "Flextronics (former Orbit)", "Suwa Electronics", "Transmeta",
 "Micron CMS", "American Computer & Digital Components Inc", "Enhance 3000 Inc", "Tower Semiconductor",
 "CPU Design", "Price Point", "Maxim Integrated Product", "Tellabs",
 "Centaur Technology", "Unigen Corporation", "Transcend Information", "Memory Card Technology",
 "CKD Corporation Ltd.", "Capital Instruments, Inc.", "Aica Kogyo, Ltd.", "Linvex Technology",
 "MSC Vertriebs GmbH", "AKM Company, Ltd.", "Dynamem, Inc.", "NERA ASA",
 "GSI Technology", "Dane-Elec (C Memory)", "Acorn Computers", "Lara Technology",
 "Oak Technology, Inc.", "Itec Memory", "Tanisys Technology", "Truevision",
 "Wintec Industries", "Super PC Memory", "MGV Memory", "Galvantech",
 "Gadzoox Nteworks", "Multi Dimensional Cons.", "GateField", "Integrated Memory System",
 "Triscend", "XaQti", "Goldenram", "Clear Logic",
 "Cimaron Communications", "Nippon Steel Semi. Corp.", "Advantage Memory", "AMCC",
 "LeCroy", "Yamaha Corporation", "Digital Microwave", "NetLogic Microsystems",
 "MIMOS Semiconductor", "Advanced Fibre", "BF Goodrich Data.", "Epigram",
 "Acbel Polytech Inc.", "Apacer Technology", "Admor Memory", "FOXCONN",
 "Quadratics Superconductor", "3COM"},
{"Camintonn Corporation", "ISOA Incorporated", "Agate Semiconductor", "ADMtek Incorporated",
 "HYPERTEC", "Adhoc Technologies", "MOSAID Technologies", "Ardent Technologies",
 "Switchcore", "Cisco Systems, Inc.", "Allayer Technologies", "WorkX AG (Wichman)",
 "Oasis Semiconductor", "Novanet Semiconductor", "E-M Solutions", "Power General",
 "Advanced Hardware Arch.", "Inova Semiconductors GmbH", "Telocity", "Delkin Devices",
 "Symagery Microsystems", "C-Port Corporation", "SiberCore Technologies", "Southland Microsystems",
 "Malleable Technologies", "Kendin Communications", "Great Technology Microcomputer", "Sanmina Corporation",
 "HADCO Corporation", "Corsair", "Actrans System Inc.", "ALPHA Technologies",
 "Silicon Laboratories, Inc. (Cygnal)", "Artesyn Technologies", "Align Manufacturing", "Peregrine Semiconductor",
 "Chameleon Systems", "Aplus Flash Technology", "MIPS Technologies", "Chrysalis ITS",
 "ADTEC Corporation", "Kentron Technologies", "Win Technologies", "Tachyon Semiconductor (former ASIC Designs Inc.)",
 "Extreme Packet Devices", "RF Micro Devices", "Siemens AG", "Sarnoff Corporation",
 "Itautec SA (former Itautec Philco SA)", "Radiata Inc.", "Benchmark Elect. (AVEX)", "Legend",
 "SpecTek Incorporated", "Hi/fn", "Enikia Incorporated", "SwitchOn Networks",
 "AANetcom Incorporated", "Micro Memory Bank", "ESS Technology", "Virata Corporation",
 "Excess Bandwidth", "West Bay Semiconductor", "DSP Group", "Newport Communications",
 "Chip2Chip Incorporated", "Phobos Corporation", "Intellitech Corporation", "Nordic VLSI ASA",
 "Ishoni Networks", "Silicon Spice", "Alchemy Semiconductor", "Agilent Technologies",
 "Centillium Communications", "W.L. Gore", "HanBit Electronics", "GlobeSpan",
 "Element 14", "Pycon", "Saifun Semiconductors", "Sibyte, Incorporated",
 "MetaLink Technologies", "Feiya Technology", "I & C Technology", "Shikatronics",
 "Elektrobit", "Megic", "Com-Tier", "Malaysia Micro Solutions",
 "Hyperchip", "Gemstone Communications", "Anadigm (former Anadyne)", "3ParData",
 "Mellanox Technologies", "Tenx Technologies", "Helix AG", "Domosys",
 "Skyup Technology", "HiNT Corporation", "Chiaro", "MDT Technologies GmbH (former MCI Computer GMBH)",
 "Exbit Technology A/S", "Integrated Technology Express", "AVED Memory", "Legerity",
 "Jasmine Networks", "Caspian Networks", "nCUBE", "Silicon Access Networks",
 "FDK Corporation", "High Bandwidth Access", "MultiLink Technology", "BRECIS",
 "World Wide Packets", "APW", "Chicory Systems", "Xstream Logic",
 "Fast-Chip", "Zucotto Wireless", "Realchip", "Galaxy Power",
 "eSilicon", "Morphics Technology", "Accelerant Networks", "Silicon Wave",
 "SandCraft", "Elpida"},
{"Solectron", "Optosys Technologies", "Buffalo (former Melco)", "TriMedia Technologies",
 "Cyan Technologies", "Global Locate", "Optillion", "Terago Communications",
 "Ikanos Communications", "Princeton Technology", "Nanya Technology", "Elite Flash Storage",
 "Mysticom", "LightSand Communications", "ATI Technologies", "Agere Systems",
 "NeoMagic", "AuroraNetics", "Golden Empire", "Mushkin",
 "Tioga Technologies", "Netlist", "TeraLogic", "Cicada Semiconductor",
 "Centon Electronics", "Tyco Electronics", "Magis Works", "Zettacom",
 "Cogency Semiconductor", "Chipcon AS", "Aspex Technology", "F5 Networks",
 "Programmable Silicon Solutions", "ChipWrights", "Acorn Networks", "Quicklogic",
 "Kingmax Semiconductor", "BOPS", "Flasys", "BitBlitz Communications",
 "eMemory Technology", "Procket Networks", "Purple Ray", "Trebia Networks",
 "Delta Electronics", "Onex Communications", "Ample Communications", "Memory Experts Intl",
 "Astute Networks", "Azanda Network Devices", "Dibcom", "Tekmos",
 "API NetWorks", "Bay Microsystems", "Firecron Ltd", "Resonext Communications",
 "Tachys Technologies", "Equator Technology", "Concept Computer", "SILCOM",
 "3Dlabs", "c't Magazine", "Sanera Systems", "Silicon Packets",
 "Viasystems Group", "Simtek", "Semicon Devices Singapore", "Satron Handelsges",
 "Improv Systems", "INDUSYS GmbH", "Corrent", "Infrant Technologies",
 "Ritek Corp", "empowerTel Networks", "Hypertec", "Cavium Networks",
 "PLX Technology", "Massana Design", "Intrinsity", "Valence Semiconductor",
 "Terawave Communications", "IceFyre Semiconductor", "Primarion", "Picochip Designs Ltd",
 "Silverback Systems", "Jade Star Technologies", "Pijnenburg Securealink",
 "takeMS - Ultron AG (former Memorysolution GmbH)", "Cambridge Silicon Radio",
 "Swissbit", "Nazomi Communications", "eWave System",
 "Rockwell Collins", "Picocel Co., Ltd.", "Alphamosaic Ltd", "Sandburst",
 "SiCon Video", "NanoAmp Solutions", "Ericsson Technology", "PrairieComm",
 "Mitac International", "Layer N Networks", "MtekVision", "Allegro Networks",
 "Marvell Semiconductors", "Netergy Microelectronic", "NVIDIA", "Internet Machines",
 "Peak Electronics", "Litchfield Communication", "Accton Technology", "Teradiant Networks",
 "Scaleo Chip (former Europe Technologies)", "Cortina Systems", "RAM Components", "Raqia Networks",
 "ClearSpeed", "Matsushita Battery", "Xelerated", "SimpleTech",
 "Utron Technology", "Astec International", "AVM gmbH", "Redux Communications",
 "Dot Hill Systems", "TeraChip"},
{"T-RAM Incorporated", "Innovics Wireless", "Teknovus", "KeyEye Communications",
 "Runcom Technologies", "RedSwitch", "Dotcast", "Silicon Mountain Memory",
 "Signia Technologies", "Pixim", "Galazar Networks", "White Electronic Designs",
 "Patriot Scientific", "Neoaxiom Corporation", "3Y Power Technology", "Scaleo Chip (former Europe Technologies)",
 "Potentia Power Systems", "C-guys Incorporated", "Digital Communications Technology Incorporated", "Silicon-Based Technology",
 "Fulcrum Microsystems", "Positivo Informatica Ltd", "XIOtech Corporation", "PortalPlayer",
 "Zhiying Software", "Parker Vision, Inc. (former Direct2Data)", "Phonex Broadband", "Skyworks Solutions",
 "Entropic Communications", "Pacific Force Technology", "Zensys A/S", "Legend Silicon Corp.",
 "sci-worx GmbH", "SMSC (former Oasis Silicon Systems)", "Renesas Electronics (former Renesas Technology)", "Raza Microelectronics",
 "Phyworks", "MediaTek", "Non-cents Productions", "US Modular",
 "Wintegra Ltd", "Mathstar", "StarCore", "Oplus Technologies",
 "Mindspeed", "Just Young Computer", "Radia Communications", "OCZ",
 "Emuzed", "LOGIC Devices", "Inphi Corporation", "Quake Technologies",
 "Vixel", "SolusTek", "Kongsberg Maritime", "Faraday Technology",
 "Altium Ltd.", "Insyte", "ARM Ltd.", "DigiVision",
 "Vativ Technologies", "Endicott Interconnect Technologies", "Pericom", "Bandspeed",
 "LeWiz Communications", "CPU Technology", "Ramaxel Technology", "DSP Group",
 "Axis Communications", "Legacy Electronics", "Chrontel", "Powerchip Semiconductor",
 "MobilEye Technologies", "Excel Semiconductor", "A-DATA Technology", "VirtualDigm",
 "G.Skill Intl", "Quanta Computer", "Yield Microelectronics", "Afa Technologies",
 "KINGBOX Technology Co. Ltd.", "Ceva", "iStor Networks", "Advance Modules",
 "Microsoft", "Open-Silicon", "Goal Semiconductor", "ARC International",
 "Simmtec", "Metanoia", "Key Stream", "Lowrance Electronics",
 "Adimos", "SiGe Semiconductor", "Fodus Communications", "Credence Systems Corp.",
 "Genesis Microchip Inc.", "Vihana, Inc.", "WIS Technologies", "GateChange Technologies",
 "High Density Devices AS", "Synopsys", "Gigaram", "Enigma Semiconductor Inc.",
 "Century Micro Inc.", "Icera Semiconductor", "Mediaworks Integrated Systems", "O'Neil Product Development",
 "Supreme Top Technology Ltd.", "MicroDisplay Corporation", "Team Group Inc.", "Sinett Corporation",
 "Toshiba Corporation", "Tensilica", "SiRF Technology", "Bacoc Inc.",
 "SMaL Camera Technologies", "Thomson SC", "Airgo Networks", "Wisair Ltd.",
 "SigmaTel", "Arkados", "Compete IT gmbH Co. KG", "Eudar Technology Inc.",
 "Focus Enhancements", "Xyratex"},
{"Specular Networks", "Patriot Memory", "U-Chip Technology Corp.", "Silicon Optix",
 "Greenfield Networks", "CompuRAM GmbH", "Stargen, Inc.", "NetCell Corporation",
 "Excalibrus Technologies Ltd", "SCM Microsystems", "Xsigo Systems, Inc.", "CHIPS & Systems Inc",
 "Tier 1 Multichip Solutions", "CWRL Labs", "Teradici", "Gigaram, Inc.",
 "g2 Microsystems", "PowerFlash Semiconductor", "P.A. Semi, Inc.", "NovaTech Solutions, S.A.",
 "c2 Microsystems, Inc.", "Level5 Networks", "COS Memory AG", "Innovasic Semiconductor",
 "02IC Co. Ltd", "Tabula, Inc.", "Crucial Technology", "Chelsio Communications",
 "Solarflare Communications", "Xambala Inc.", "EADS Astrium", "Terra Semiconductor Inc. (former ATO Semicon Co. Ltd.)",
 "Imaging Works, Inc.", "Astute Networks, Inc.", "Tzero", "Emulex",
 "Power-One", "Pulse~LINK Inc.", "Hon Hai Precision Industry", "White Rock Networks Inc.",
 "Telegent Systems USA, Inc.", "Atrua Technologies, Inc.", "Acbel Polytech Inc.",
 "eRide Inc.","ULi Electronics Inc.", "Magnum Semiconductor Inc.", "neoOne Technology, Inc.",
 "Connex Technology, Inc.", "Stream Processors, Inc.", "Focus Enhancements", "Telecis Wireless, Inc.",
 "uNav Microelectronics", "Tarari, Inc.", "Ambric, Inc.", "Newport Media, Inc.", "VMTS",
 "Enuclia Semiconductor, Inc.", "Virtium Technology Inc.", "Solid State System Co., Ltd.", "Kian Tech LLC",
 "Artimi", "Power Quotient International", "Avago Technologies", "ADTechnology", "Sigma Designs",
 "SiCortex, Inc.", "Ventura Technology Group", "eASIC", "M.H.S. SAS", "Micro Star International",
 "Rapport Inc.", "Makway International", "Broad Reach Engineering Co.",
 "Semiconductor Mfg Intl Corp", "SiConnect", "FCI USA Inc.", "Validity Sensors",
 "Coney Technology Co. Ltd.", "Spans Logic", "Neterion Inc.", "Qimonda",
 "New Japan Radio Co. Ltd.", "Velogix", "Montalvo Systems", "iVivity Inc.", "Walton Chaintech",
 "AENEON", "Lorom Industrial Co. Ltd.", "Radiospire Networks", "Sensio Technologies, Inc.",
 "Nethra Imaging", "Hexon Technology Pte Ltd", "CompuStocx (CSX)", "Methode Electronics, Inc.",
 "Connect One Ltd.", "Opulan Technologies", "Septentrio NV", "Goldenmars Technology Inc.",
 "Kreton Corporation", "Cochlear Ltd.", "Altair Semiconductor", "NetEffect, Inc.",
 "Spansion, Inc.", "Taiwan Semiconductor Mfg", "Emphany Systems Inc.",
 "ApaceWave Technologies", "Mobilygen Corporation", "Tego", "Cswitch Corporation",
 "Haier (Beijing) IC Design Co.", "MetaRAM", "Axel Electronics Co. Ltd.", "Tilera Corporation",
 "Aquantia", "Vivace Semiconductor", "Redpine Signals", "Octalica", "InterDigital Communications",
 "Avant Technology", "Asrock, Inc.", "Availink", "Quartics, Inc.", "Element CXI",
 "Innovaciones Microelectronicas", "VeriSilicon Microelectronics", "W5 Networks"},
{"MOVEKING", "Mavrix Technology, Inc.", "CellGuide Ltd.", "Faraday Technology",
 "Diablo Technologies, Inc.", "Jennic", "Octasic", "Molex Incorporated", "3Leaf Networks",
 "Bright Micron Technology", "Netxen", "NextWave Broadband Inc.", "DisplayLink", "ZMOS Technology",
 "Tec-Hill", "Multigig, Inc.", "Amimon", "Euphonic Technologies, Inc.", "BRN Phoenix",
 "InSilica", "Ember Corporation", "Avexir Technologies Corporation", "Echelon Corporation",
 "Edgewater Computer Systems", "XMOS Semiconductor Ltd.", "GENUSION, Inc.", "Memory Corp NV",
 "SiliconBlue Technologies", "Rambus Inc.", "Andes Technology Corporation", "Coronis Systems",
 "Achronix Semiconductor", "Siano Mobile Silicon Ltd.", "Semtech Corporation", "Pixelworks Inc.",
 "Gaisler Research AB", "Teranetics", "Toppan Printing Co. Ltd.", "Kingxcon",
 "Silicon Integrated Systems", "I-O Data Device, Inc.", "NDS Americas Inc.", "Solomon Systech Limited",
 "On Demand Microelectronics", "Amicus Wireless Inc.", "SMARDTV SNC", "Comsys Communication Ltd.",
 "Movidia Ltd.", "Javad GNSS, Inc.", "Montage Technology Group", "Trident Microsystems", "Super Talent",
 "Optichron, Inc.", "Future Waves UK Ltd.", "SiBEAM, Inc.", "Inicore, Inc.", "Virident Systems",
 "M2000, Inc.", "ZeroG Wireless, Inc.", "Gingle Technology Co. Ltd.", "Space Micro Inc.", "Wilocity",
 "Novafora, Inc.", "iKoa Corporation", "ASint Technology", "Ramtron", "Plato Networks Inc.",
 "IPtronics AS", "Infinite-Memories", "Parade Technologies Inc.", "Dune Networks",
 "GigaDevice Semiconductor", "Modu Ltd.", "CEITEC", "Northrop Grumman", "XRONET Corporation",
 "Sicon Semiconductor AB", "Atla Electronics Co. Ltd.", "TOPRAM Technology", "Silego Technology Inc.",
 "Kinglife", "Ability Industries Ltd.", "Silicon Power Computer & Communications",
 "Augusta Technology, Inc.", "Nantronics Semiconductors", "Hilscher Gesellschaft", "Quixant Ltd.",
 "Percello Ltd.", "NextIO Inc.", "Scanimetrics Inc.", "FS-Semi Company Ltd.", "Infinera Corporation",
 "SandForce Inc.", "Lexar Media", "Teradyne Inc.", "Memory Exchange Corp.", "Suzhou Smartek Electronics",
 "Avantium Corporation", "ATP Electronics Inc.", "Valens Semiconductor Ltd", "Agate Logic, Inc.",
 "Netronome", "Zenverge, Inc.", "N-trig Ltd", "SanMax Technologies Inc.", "Contour Semiconductor Inc.",
 "TwinMOS", "Silicon Systems, Inc.", "V-Color Technology Inc.", "Certicom Corporation", "JSC ICC Milandr",
 "PhotoFast Global Inc.", "InnoDisk Corporation", "Muscle Power", "Energy Micro", "Innofidei",
 "CopperGate Communications", "Holtek Semiconductor Inc.", "Myson Century, Inc.", "FIDELIX",
 "Red Digital Cinema", "Densbits Technology", "Zempro", "MoSys", "Provigent", "Triad Semiconductor, Inc."},
{"Siklu Communication Ltd.", "A Force Manufacturing Ltd.", "Strontium", "Abilis Systems", "Siglead, Inc.",
 "Ubicom, Inc.", "Unifosa Corporation", "Stretch, Inc.", "Lantiq Deutschland GmbH", "Visipro",
 "EKMemory", "Microelectronics Institute ZTE", "Cognovo Ltd.", "Carry Technology Co. Ltd.", "Nokia",
 "King Tiger Technology", "Sierra Wireless", "HT Micron", "Albatron Technology Co. Ltd.",
 "Leica Geosystems AG", "BroadLight", "AEXEA", "ClariPhy Communications, Inc.", "Green Plug",
 "Design Art Networks", "Mach Xtreme Technology Ltd.", "ATO Solutions Co. Ltd.", "Ramsta",
 "Greenliant Systems, Ltd.", "Teikon", "Antec Hadron", "NavCom Technology, Inc.",
 "Shanghai Fudan Microelectronics", "Calxeda, Inc.", "JSC EDC Electronics", "Kandit Technology Co. Ltd.",
 "Ramos Technology", "Goldenmars Technology", "XeL Technology Inc.", "Newzone Corporation",
 "ShenZhen MercyPower Tech", "Nanjing Yihuo Technology", "Nethra Imaging Inc.", "SiTel Semiconductor BV",
 "SolidGear Corporation", "Topower Computer Ind Co Ltd.", "Wilocity", "Profichip GmbH",
 "Gerad Technologies", "Ritek Corporation", "Gomos Technology Limited", "Memoright Corporation",
 "D-Broad, Inc.", "HiSilicon Technologies", "Syndiant Inc.", "Enverv Inc.", "Cognex",
 "Xinnova Technology Inc.", "Ultron AG", "Concord Idea Corporation", "AIM Corporation",
 "Lifetime Memory Products", "Ramsway", "Recore Systems BV", "Haotian Jinshibo Science Tech",
 "Being Advanced Memory", "Adesto Technologies", "Giantec Semiconductor, Inc.", "HMD Electronics AG",
 "Gloway International (HK)", "Kingcore", "Anucell Technology Holding",
 "Accord Software & Systems Pvt. Ltd.", "Active-Semi Inc.", "Denso Corporation", "TLSI Inc.",
 "Shenzhen Daling Electronic Co. Ltd.", "Mustang", "Orca Systems", "Passif Semiconductor",
 "GigaDevice Semiconductor (Beijing) Inc.", "Memphis Electronic", "Beckhoff Automation GmbH",
 "Harmony Semiconductor Corp (former ProPlus Design Solutions)", "Air Computers SRL", "TMT Memory",
 "Eorex Corporation", "Xingtera", "Netsol", "Bestdon Technology Co. Ltd.", "Baysand Inc.",
 "Uroad Technology Co. Ltd. (former Triple Grow Industrial Ltd.)", "Wilk Elektronik S.A.",
 "AAI", "Harman", "Berg Microelectronics Inc.", "ASSIA, Inc.", "Visiontek Products LLC",
 "OCMEMORY", "Welink Solution Inc.", "Shark Gaming", "Avalanche Technology",
 "R&D Center ELVEES OJSC", "KingboMars Technology Co. Ltd.",
 "High Bridge Solutions Industria Eletronica", "Transcend Technology Co. Ltd.",
 "Everspin Technologies", "Hon-Hai Precision", "Smart Storage Systems", "Toumaz Group",
 "Zentel Electronics Corporation", "Panram International Corporation",
 "Silicon Space Technology"}
};

/**
 * struct cxl_ctx - library user context to find "nd" instances
 *
 * Instantiate with cxl_new(), which takes an initial reference.  Free
 * the context by dropping the reference count to zero with
 * cxl_unref(), or take additional references with cxl_ref()
 * @timeout: default library timeout in milliseconds
 */
struct cxl_ctx {
	/* log_ctx must be first member for cxl_set_log_fn compat */
	struct log_ctx ctx;
	int refcount;
	void *userdata;
	int memdevs_init;
	struct list_head memdevs;
	struct kmod_ctx *kmod_ctx;
	void *private_data;
};

static void free_memdev(struct cxl_memdev *memdev, struct list_head *head)
{
	if (head)
		list_del_from(head, &memdev->list);
	kmod_module_unref(memdev->module);
	free(memdev->firmware_version);
	free(memdev->dev_buf);
	free(memdev->dev_path);
	free(memdev);
}

static void hexdump_mbox(struct cxl_cmd *cmd, struct cxl_ctx *ctx)
{
	u8 *buf;
	buf = (u8*) cmd->send_cmd->in.payload;
	dbg(ctx, "\n============== SEND_CMD HEXDUMP =============\n \
	id (u32):\nHex: %x\tDec: %d\n \
	flags (u32):\nHex: %x\tDec: %d\n \
	raw.opcode (u16):\nHex: %x\tDec: %d\n \
	in.size (s32):\nHex: %x\tDec: %d\n \
	in.payload (u64, pointer to buffer):\nHex: %llx\tDec: %lld\n", cmd->send_cmd->id, cmd->send_cmd->id, cmd->send_cmd->flags, cmd->send_cmd->flags, cmd->send_cmd->raw.opcode, cmd->send_cmd->raw.opcode, cmd->send_cmd->in.size, cmd->send_cmd->in.size, cmd->send_cmd->in.payload, cmd->send_cmd->in.payload);
	dbg_s(ctx, "Input payload:");
	for (int i = 0; i < cmd->send_cmd->in.size; i++) {
		if (i % 16 == 0)
		{
			dbg_s(ctx, "\n%08x  %02x ", i, buf[i]);
		}
		else
		{
			dbg_s(ctx, "%02x ", buf[i]);
		}
	}
	dbg_s(ctx, "\n============== END SEND_CMD HEXDUMP =============\n");

}

/**
 * cxl_get_userdata - retrieve stored data pointer from library context
 * @ctx: cxl library context
 *
 * This might be useful to access from callbacks like a custom logging
 * function.
 */
CXL_EXPORT void *cxl_get_userdata(struct cxl_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	return ctx->userdata;
}

/**
 * cxl_set_userdata - store custom @userdata in the library context
 * @ctx: cxl library context
 * @userdata: data pointer
 */
CXL_EXPORT void cxl_set_userdata(struct cxl_ctx *ctx, void *userdata)
{
	if (ctx == NULL)
		return;
	ctx->userdata = userdata;
}

CXL_EXPORT void cxl_set_private_data(struct cxl_ctx *ctx, void *data)
{
	ctx->private_data = data;
}

CXL_EXPORT void *cxl_get_private_data(struct cxl_ctx *ctx)
{
	return ctx->private_data;
}

/**
 * cxl_new - instantiate a new library context
 * @ctx: context to establish
 *
 * Returns zero on success and stores an opaque pointer in ctx.  The
 * context is freed by cxl_unref(), i.e. cxl_new() implies an
 * internal cxl_ref().
 */
CXL_EXPORT int cxl_new(struct cxl_ctx **ctx)
{
	struct kmod_ctx *kmod_ctx;
	struct cxl_ctx *c;
	int rc = 0;

	c = calloc(1, sizeof(struct cxl_ctx));
	if (!c)
		return -ENOMEM;

	kmod_ctx = kmod_new(NULL, NULL);
	if (check_kmod(kmod_ctx) != 0) {
		rc = -ENXIO;
		goto out;
	}

	c->refcount = 1;
	log_init(&c->ctx, "libcxl", "CXL_LOG");
	info(c, "ctx %p created\n", c);
	dbg(c, "log_priority=%d\n", c->ctx.log_priority);
	*ctx = c;
	list_head_init(&c->memdevs);
	c->kmod_ctx = kmod_ctx;

	return 0;
out:
	free(c);
	return rc;
}

/**
 * cxl_ref - take an additional reference on the context
 * @ctx: context established by cxl_new()
 */
CXL_EXPORT struct cxl_ctx *cxl_ref(struct cxl_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	ctx->refcount++;
	return ctx;
}

/**
 * cxl_unref - drop a context reference count
 * @ctx: context established by cxl_new()
 *
 * Drop a reference and if the resulting reference count is 0 destroy
 * the context.
 */
CXL_EXPORT void cxl_unref(struct cxl_ctx *ctx)
{
	struct cxl_memdev *memdev, *_d;

	if (ctx == NULL)
		return;
	ctx->refcount--;
	if (ctx->refcount > 0)
		return;

	list_for_each_safe(&ctx->memdevs, memdev, _d, list)
		free_memdev(memdev, &ctx->memdevs);

	kmod_unref(ctx->kmod_ctx);
	info(ctx, "context %p released\n", ctx);
	free(ctx);
}

/**
 * cxl_set_log_fn - override default log routine
 * @ctx: cxl library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be overridden by a
 * custom function, to plug log messages into the user's logging
 * functionality.
 */
CXL_EXPORT void cxl_set_log_fn(struct cxl_ctx *ctx,
		void (*cxl_log_fn)(struct cxl_ctx *ctx, int priority,
			const char *file, int line, const char *fn,
			const char *format, va_list args))
{
	ctx->ctx.log_fn = (log_fn) cxl_log_fn;
	info(ctx, "custom logging function %p registered\n", cxl_log_fn);
}

/**
 * cxl_get_log_priority - retrieve current library loglevel (syslog)
 * @ctx: cxl library context
 */
CXL_EXPORT int cxl_get_log_priority(struct cxl_ctx *ctx)
{
	return ctx->ctx.log_priority;
}

/**
 * cxl_set_log_priority - set log verbosity
 * @priority: from syslog.h, LOG_ERR, LOG_INFO, LOG_DEBUG
 *
 * Note: LOG_DEBUG requires library be built with "configure --enable-debug"
 */
CXL_EXPORT void cxl_set_log_priority(struct cxl_ctx *ctx, int priority)
{
	ctx->ctx.log_priority = priority;
}

static void *add_cxl_memdev(void *parent, int id, const char *cxlmem_base)
{
	const char *devname = devpath_to_devname(cxlmem_base);
	char *path = calloc(1, strlen(cxlmem_base) + 100);
	struct cxl_ctx *ctx = parent;
	struct cxl_memdev *memdev, *memdev_dup;
	char buf[SYSFS_ATTR_SIZE];
	struct stat st;

	if (!path)
		return NULL;
	dbg(ctx, "%s: base: \'%s\'\n", __func__, cxlmem_base);

	memdev = calloc(1, sizeof(*memdev));
	if (!memdev)
		goto err_dev;
	memdev->id = id;
	memdev->ctx = ctx;

	sprintf(path, "/dev/cxl/%s", devname);
	if (stat(path, &st) < 0)
		goto err_read;
	memdev->major = major(st.st_rdev);
	memdev->minor = minor(st.st_rdev);

	sprintf(path, "%s/pmem/size", cxlmem_base);
	if (sysfs_read_attr(ctx, path, buf) < 0)
		goto err_read;
	memdev->pmem_size = strtoull(buf, NULL, 0);

	sprintf(path, "%s/ram/size", cxlmem_base);
	if (sysfs_read_attr(ctx, path, buf) < 0)
		goto err_read;
	memdev->ram_size = strtoull(buf, NULL, 0);

	sprintf(path, "%s/payload_max", cxlmem_base);
	if (sysfs_read_attr(ctx, path, buf) < 0)
		goto err_read;
	memdev->payload_max = strtoull(buf, NULL, 0);
	if (memdev->payload_max < 0)
		goto err_read;

	sprintf(path, "%s/label_storage_size", cxlmem_base);
	if (sysfs_read_attr(ctx, path, buf) < 0)
		goto err_read;
	memdev->lsa_size = strtoull(buf, NULL, 0);
	if (memdev->lsa_size == ULLONG_MAX)
		goto err_read;

	memdev->dev_path = strdup(cxlmem_base);
	if (!memdev->dev_path)
		goto err_read;

	sprintf(path, "%s/firmware_version", cxlmem_base);
	if (sysfs_read_attr(ctx, path, buf) < 0)
		goto err_read;

	memdev->firmware_version = strdup(buf);
	if (!memdev->firmware_version)
		goto err_read;

	memdev->dev_buf = calloc(1, strlen(cxlmem_base) + 50);
	if (!memdev->dev_buf)
		goto err_read;
	memdev->buf_len = strlen(cxlmem_base) + 50;

	cxl_memdev_foreach(ctx, memdev_dup)
		if (memdev_dup->id == memdev->id) {
			free_memdev(memdev, NULL);
			free(path);
			return memdev_dup;
		}

	list_add(&ctx->memdevs, &memdev->list);
	free(path);
	return memdev;

 err_read:
	free(memdev->firmware_version);
	free(memdev->dev_buf);
	free(memdev->dev_path);
	free(memdev);
 err_dev:
	free(path);
	return NULL;
}

static void cxl_memdevs_init(struct cxl_ctx *ctx)
{
	if (ctx->memdevs_init)
		return;

	ctx->memdevs_init = 1;

	sysfs_device_parse(ctx, "/sys/bus/cxl/devices", "mem", ctx,
			   add_cxl_memdev);
}

CXL_EXPORT struct cxl_ctx *cxl_memdev_get_ctx(struct cxl_memdev *memdev)
{
	return memdev->ctx;
}

CXL_EXPORT struct cxl_memdev *cxl_memdev_get_first(struct cxl_ctx *ctx)
{
	cxl_memdevs_init(ctx);

	return list_top(&ctx->memdevs, struct cxl_memdev, list);
}

CXL_EXPORT struct cxl_memdev *cxl_memdev_get_next(struct cxl_memdev *memdev)
{
	struct cxl_ctx *ctx = memdev->ctx;

	return list_next(&ctx->memdevs, memdev, list);
}

CXL_EXPORT int cxl_memdev_get_id(struct cxl_memdev *memdev)
{
	return memdev->id;
}

CXL_EXPORT const char *cxl_memdev_get_devname(struct cxl_memdev *memdev)
{
	return devpath_to_devname(memdev->dev_path);
}

CXL_EXPORT int cxl_memdev_get_major(struct cxl_memdev *memdev)
{
	return memdev->major;
}

CXL_EXPORT int cxl_memdev_get_minor(struct cxl_memdev *memdev)
{
	return memdev->minor;
}

CXL_EXPORT unsigned long long cxl_memdev_get_pmem_size(struct cxl_memdev *memdev)
{
	return memdev->pmem_size;
}

CXL_EXPORT unsigned long long cxl_memdev_get_ram_size(struct cxl_memdev *memdev)
{
	return memdev->ram_size;
}

CXL_EXPORT const char *cxl_memdev_get_firmware_verison(struct cxl_memdev *memdev)
{
	return memdev->firmware_version;
}

CXL_EXPORT size_t cxl_memdev_get_lsa_size(struct cxl_memdev *memdev)
{
	return memdev->lsa_size;
}

CXL_EXPORT int cxl_memdev_is_active(struct cxl_memdev *memdev)
{
	/*
	 * TODO: Currently memdevs are always considered inactive. Once we have
	 * cxl_bus drivers that are bound/unbound to memdevs, we'd use that to
	 * determine the active/inactive state.
	 */
	return 0;
}

CXL_EXPORT void cxl_cmd_unref(struct cxl_cmd *cmd)
{
	if (!cmd)
		return;
	if (--cmd->refcount == 0) {
		free(cmd->query_cmd);
		free(cmd->send_cmd);
		free(cmd->input_payload);
		free(cmd->output_payload);
		free(cmd);
	}
}

CXL_EXPORT void cxl_cmd_ref(struct cxl_cmd *cmd)
{
	cmd->refcount++;
}

static int cxl_cmd_alloc_query(struct cxl_cmd *cmd, int num_cmds)
{
	size_t size;

	if (!cmd)
		return -EINVAL;

	if (cmd->query_cmd != NULL)
		free(cmd->query_cmd);

	size = sizeof(struct cxl_mem_query_commands) +
			(num_cmds * sizeof(struct cxl_command_info));
	cmd->query_cmd = calloc(1, size);
	if (!cmd->query_cmd)
		return -ENOMEM;

	cmd->query_cmd->n_commands = num_cmds;

	return 0;
}

static struct cxl_cmd *cxl_cmd_new(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	size_t size;

	size = sizeof(*cmd);
	cmd = calloc(1, size);
	if (!cmd)
		return NULL;

	cxl_cmd_ref(cmd);
	cmd->memdev = memdev;

	return cmd;
}

static int __do_cmd(struct cxl_cmd *cmd, int ioctl_cmd, int fd)
{
	void *cmd_buf;
	int rc;

	switch (ioctl_cmd) {
	case CXL_MEM_QUERY_COMMANDS:
		cmd_buf = cmd->query_cmd;
		break;
	case CXL_MEM_SEND_COMMAND:
		cmd_buf = cmd->send_cmd;
		if (cxl_get_log_priority(cmd->memdev->ctx) == LOG_DEBUG)
		{
			hexdump_mbox(cmd, cmd->memdev->ctx);
		}
		break;
	default:
		return -EINVAL;
	}
	rc = ioctl(fd, ioctl_cmd, cmd_buf);
	if (rc < 0)
		rc = -errno;

	return rc;
}

static int do_cmd(struct cxl_cmd *cmd, int ioctl_cmd)
{
	char *path;
	struct stat st;
	unsigned int major, minor;
	int rc = 0, fd;
	struct cxl_memdev *memdev = cmd->memdev;
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	const char *devname = cxl_memdev_get_devname(memdev);

	major = cxl_memdev_get_major(memdev);
	minor = cxl_memdev_get_minor(memdev);

	if (asprintf(&path, "/dev/cxl/%s", devname) < 0)
		return -ENOMEM;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		err(ctx, "failed to open %s: %s\n", path, strerror(errno));
		rc = -errno;
		goto out;
	}

	if (fstat(fd, &st) >= 0 && S_ISCHR(st.st_mode)
			&& major(st.st_rdev) == major
			&& minor(st.st_rdev) == minor) {
		rc = __do_cmd(cmd, ioctl_cmd, fd);
	} else {
		err(ctx, "failed to validate %s as a CXL memdev node\n", path);
		rc = -ENXIO;
	}
	close(fd);
out:
	free(path);
	return rc;
}

static int alloc_do_query(struct cxl_cmd *cmd, int num_cmds)
{
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(cmd->memdev);
	int rc;

	rc = cxl_cmd_alloc_query(cmd, num_cmds);
	if (rc)
		return rc;

	rc = do_cmd(cmd, CXL_MEM_QUERY_COMMANDS);
	if (rc < 0)
		err(ctx, "%s: query commands failed: %s\n",
			cxl_memdev_get_devname(cmd->memdev),
			strerror(-rc));
	return rc;
}

static int cxl_cmd_do_query(struct cxl_cmd *cmd)
{
	struct cxl_memdev *memdev = cmd->memdev;
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	const char *devname = cxl_memdev_get_devname(memdev);
	int rc, n_commands;

	switch (cmd->query_status) {
	case CXL_CMD_QUERY_OK:
		return 0;
	case CXL_CMD_QUERY_UNSUPPORTED:
		return -EOPNOTSUPP;
	case CXL_CMD_QUERY_NOT_RUN:
		break;
	default:
		err(ctx, "%s: Unknown query_status %d\n",
			devname, cmd->query_status);
		return -EINVAL;
	}

	rc = alloc_do_query(cmd, 0);
	if (rc)
		return rc;

	n_commands = cmd->query_cmd->n_commands;
	dbg(ctx, "%s: supports %d commands\n", devname, n_commands);

	return alloc_do_query(cmd, n_commands);
}

static int cxl_cmd_validate(struct cxl_cmd *cmd, u32 cmd_id)
{
	struct cxl_memdev *memdev = cmd->memdev;
	struct cxl_mem_query_commands *query = cmd->query_cmd;
	const char *devname = cxl_memdev_get_devname(memdev);
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	u32 i;

	for (i = 0; i < query->n_commands; i++) {
		struct cxl_command_info *cinfo = &query->commands[i];
		const char *cmd_name = cxl_command_names[cinfo->id].name;

		if (cinfo->id != cmd_id)
			continue;

		dbg(ctx, "%s: %s: in: %d, out %d, flags: %#08x\n",
			devname, cmd_name, cinfo->size_in,
			cinfo->size_out, cinfo->flags);

		cmd->query_idx = i;
		cmd->query_status = CXL_CMD_QUERY_OK;
		return 0;
	}
	cmd->query_status = CXL_CMD_QUERY_UNSUPPORTED;
	return -EOPNOTSUPP;
}

CXL_EXPORT int cxl_cmd_set_input_payload(struct cxl_cmd *cmd, void *buf,
		int size)
{
	struct cxl_memdev *memdev = cmd->memdev;

	if (size > memdev->payload_max || size < 0)
		return -EINVAL;

	if (!buf) {

		/* If the user didn't supply a buffer, allocate it */
		cmd->input_payload = calloc(1, size);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
	} else {
		/*
		 * Use user-buffer as is. If an automatic allocation was
		 * previously made (based on a fixed size from query),
		 * it will get freed during unref.
		 */
		cmd->send_cmd->in.payload = (u64)buf;
	}
	cmd->send_cmd->in.size = size;

	return 0;
}

CXL_EXPORT int cxl_cmd_set_output_payload(struct cxl_cmd *cmd, void *buf,
		int size)
{
	struct cxl_memdev *memdev = cmd->memdev;

	if (size > memdev->payload_max || size < 0)
		return -EINVAL;

	if (!buf) {

		/* If the user didn't supply a buffer, allocate it */
		cmd->output_payload = calloc(1, size);
		if (!cmd->output_payload)
			return -ENOMEM;
		cmd->send_cmd->out.payload = (u64)cmd->output_payload;
	} else {
		/*
		 * Use user-buffer as is. If an automatic allocation was
		 * previously made (based on a fixed size from query),
		 * it will get freed during unref.
		 */
		cmd->send_cmd->out.payload = (u64)buf;
	}
	cmd->send_cmd->out.size = size;

	return 0;
}

static int cxl_cmd_alloc_send(struct cxl_cmd *cmd, u32 cmd_id)
{
	struct cxl_mem_query_commands *query = cmd->query_cmd;
	struct cxl_command_info *cinfo = &query->commands[cmd->query_idx];
	size_t size;

	if (!query)
		return -EINVAL;

	size = sizeof(struct cxl_send_command);
	cmd->send_cmd = calloc(1, size);
	if (!cmd->send_cmd)
		return -ENOMEM;

	if (cinfo->id != cmd_id)
		return -EINVAL;

	cmd->send_cmd->id = cmd_id;

	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	if (cinfo->size_out < 0)
		cinfo->size_out = cmd->memdev->payload_max; // -1 will require update

	if (cinfo->size_out > 0) {
		cmd->output_payload = calloc(1, cinfo->size_out);
		if (!cmd->output_payload)
			return -ENOMEM;
		cmd->send_cmd->out.payload = (u64)cmd->output_payload;
		cmd->send_cmd->out.size = cinfo->size_out;
	}

	return 0;
}

static struct cxl_cmd *cxl_cmd_new_generic(struct cxl_memdev *memdev,
		u32 cmd_id)
{
	const char *devname = cxl_memdev_get_devname(memdev);
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	struct cxl_cmd *cmd;
	int rc;

	cmd = cxl_cmd_new(memdev);
	if (!cmd)
		return NULL;

	rc = cxl_cmd_do_query(cmd);
	if (rc) {
		err(ctx, "%s: query returned: %s\n", devname, strerror(-rc));
		goto fail;
	}

	rc = cxl_cmd_validate(cmd, cmd_id);
	if (rc) {
		errno = -rc;
		goto fail;
	}

	rc = cxl_cmd_alloc_send(cmd, cmd_id);
	if (rc) {
		errno = -rc;
		goto fail;
	}

	return cmd;

fail:
	cxl_cmd_unref(cmd);
	return NULL;
}

CXL_EXPORT const char *cxl_cmd_get_devname(struct cxl_cmd *cmd)
{
	return cxl_memdev_get_devname(cmd->memdev);
}

#define cmd_get_int(cmd, n, N, field) \
do { \
	struct cxl_cmd_##n *c = (void *)cmd->send_cmd->out.payload; \
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_##N) \
		return EINVAL; \
	if (cmd->status < 0) \
		return cmd->status; \
	return le32_to_cpu(c->field); \
} while(0);

CXL_EXPORT struct cxl_cmd *cxl_cmd_new_get_health_info(
		struct cxl_memdev *memdev)
{
	return cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_GET_HEALTH_INFO);
}

#define cmd_health_get_int(c, f) \
do { \
	cmd_get_int(c, get_health_info, GET_HEALTH_INFO, f); \
} while (0);

CXL_EXPORT int cxl_cmd_get_health_info_get_health_status(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, health_status);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_media_status(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, media_status);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_ext_status(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, ext_status);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_life_used(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, life_used);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_temperature(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, temperature);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_dirty_shutdowns(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, dirty_shutdowns);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_volatile_errors(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, volatile_errors);
}

CXL_EXPORT int cxl_cmd_get_health_info_get_pmem_errors(struct cxl_cmd *cmd)
{
	cmd_health_get_int(cmd, pmem_errors);
}

CXL_EXPORT struct cxl_cmd *cxl_cmd_new_identify(struct cxl_memdev *memdev)
{
	return cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_IDENTIFY);
}

CXL_EXPORT int cxl_cmd_identify_get_fw_rev(struct cxl_cmd *cmd, char *fw_rev,
		int fw_len)
{
	struct cxl_cmd_identify *id = (void *)cmd->send_cmd->out.payload;

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_IDENTIFY)
		return -EINVAL;
	if (cmd->status < 0)
		return cmd->status;

	if (fw_len > 0)
		memcpy(fw_rev, id->fw_revision,
			min(fw_len, CXL_CMD_IDENTIFY_FW_REV_LENGTH));
	return 0;
}

CXL_EXPORT unsigned long long cxl_cmd_identify_get_partition_align(
		struct cxl_cmd *cmd)
{
	struct cxl_cmd_identify *id = (void *)cmd->send_cmd->out.payload;

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_IDENTIFY)
		return -EINVAL;
	if (cmd->status < 0)
		return cmd->status;

	return le64_to_cpu(id->partition_align);
}

CXL_EXPORT unsigned int cxl_cmd_identify_get_lsa_size(struct cxl_cmd *cmd)
{
	struct cxl_cmd_identify *id = (void *)cmd->send_cmd->out.payload;

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_IDENTIFY)
		return -EINVAL;
	if (cmd->status < 0)
		return cmd->status;

	return le32_to_cpu(id->lsa_size);
}

CXL_EXPORT struct cxl_cmd *cxl_cmd_new_raw(struct cxl_memdev *memdev,
		int opcode)
{
	struct cxl_cmd *cmd;

	/* opcode '0' is reserved */
	if (opcode <= 0) {
		errno = EINVAL;
		return NULL;
	}

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_RAW);
	if (!cmd)
		return NULL;

	cmd->send_cmd->raw.opcode = opcode;
	return cmd;
}

CXL_EXPORT struct cxl_cmd *cxl_cmd_new_get_lsa(struct cxl_memdev *memdev,
		unsigned int offset, unsigned int length)
{
	struct cxl_cmd_get_lsa_in *get_lsa;
	struct cxl_cmd *cmd;

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_GET_LSA);
	if (!cmd)
		return NULL;

	get_lsa = (void *)cmd->send_cmd->in.payload;
	get_lsa->offset = cpu_to_le32(offset);
	get_lsa->length = cpu_to_le32(length);
	return cmd;
}

#define cmd_get_void(cmd, N) \
do { \
	void *p = (void *)cmd->send_cmd->out.payload; \
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_##N) \
		return NULL; \
	if (cmd->status < 0) \
		return NULL; \
	return p; \
} while(0);

CXL_EXPORT void *cxl_cmd_get_lsa_get_payload(struct cxl_cmd *cmd)
{
	cmd_get_void(cmd, GET_LSA);
}

CXL_EXPORT int cxl_cmd_submit(struct cxl_cmd *cmd)
{
	struct cxl_memdev *memdev = cmd->memdev;
	const char *devname = cxl_memdev_get_devname(memdev);
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	int rc;

	switch (cmd->query_status) {
	case CXL_CMD_QUERY_OK:
		break;
	case CXL_CMD_QUERY_UNSUPPORTED:
		return -EOPNOTSUPP;
	case CXL_CMD_QUERY_NOT_RUN:
		return -EINVAL;
	default:
		err(ctx, "%s: Unknown query_status %d\n",
			devname, cmd->query_status);
		return -EINVAL;
	}

	dbg(ctx, "%s: submitting SEND cmd: in: %d, out: %d\n", devname,
		cmd->send_cmd->in.size, cmd->send_cmd->out.size);
	rc = do_cmd(cmd, CXL_MEM_SEND_COMMAND);
	if (rc < 0)
		err(ctx, "%s: send command failed: %s\n",
			devname, strerror(-rc));
	cmd->status = cmd->send_cmd->retval;
	dbg(ctx, "%s: got SEND cmd: in: %d, out: %d, retval: %d\n", devname,
		cmd->send_cmd->in.size, cmd->send_cmd->out.size, cmd->status);

	return rc;
}

CXL_EXPORT int cxl_cmd_get_mbox_status(struct cxl_cmd *cmd)
{
	return cmd->status;
}

CXL_EXPORT int cxl_cmd_get_out_size(struct cxl_cmd *cmd)
{
	return cmd->send_cmd->out.size;
}

CXL_EXPORT struct cxl_cmd *cxl_cmd_new_set_lsa(struct cxl_memdev *memdev,
		void *lsa_buf, unsigned int offset, unsigned int length)
{
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	struct cxl_cmd_set_lsa *set_lsa;
	struct cxl_cmd *cmd;
	int rc;

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_SET_LSA);
	if (!cmd)
		return NULL;

	/* this will allocate 'in.payload' */
	rc = cxl_cmd_set_input_payload(cmd, NULL, sizeof(*set_lsa) + length);
	if (rc) {
		err(ctx, "%s: cmd setup failed: %s\n",
			cxl_memdev_get_devname(memdev), strerror(-rc));
		goto out_fail;
	}
	set_lsa = (void *)cmd->send_cmd->in.payload;
	set_lsa->offset = cpu_to_le32(offset);
	memcpy(set_lsa->lsa_data, lsa_buf, length);

	return cmd;

out_fail:
	cxl_cmd_unref(cmd);
	return NULL;
}

enum lsa_op {
	LSA_OP_GET,
	LSA_OP_SET,
	LSA_OP_ZERO,
};

static int lsa_op(struct cxl_memdev *memdev, int op, void **buf,
		size_t length, size_t offset)
{
	const char *devname = cxl_memdev_get_devname(memdev);
	struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);
	struct cxl_cmd *cmd;
	void *zero_buf = NULL;
	int rc = 0;

	if (op != LSA_OP_ZERO && (buf == NULL || *buf == NULL)) {
		err(ctx, "%s: LSA buffer cannot be NULL\n", devname);
		return -EINVAL;
	}

	/* TODO: handle the case for offset + len > mailbox payload size */
	switch (op) {
	case LSA_OP_GET:
		if (length == 0)
			length = memdev->lsa_size;
		cmd = cxl_cmd_new_get_lsa(memdev, offset, length);
		if (!cmd)
			return -ENOMEM;
		rc = cxl_cmd_set_output_payload(cmd, *buf, length);
		if (rc) {
			err(ctx, "%s: cmd setup failed: %s\n",
			    cxl_memdev_get_devname(memdev), strerror(-rc));
			goto out;
		}
		break;
	case LSA_OP_ZERO:
		if (length == 0)
			length = memdev->lsa_size;
		zero_buf = calloc(1, length);
		if (!zero_buf)
			return -ENOMEM;
		buf = &zero_buf;
		/* fall through */
	case LSA_OP_SET:
		cmd = cxl_cmd_new_set_lsa(memdev, *buf, offset, length);
		if (!cmd) {
			rc = -ENOMEM;
			goto out_free;
		}
		break;
	default:
		return -EOPNOTSUPP;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		err(ctx, "%s: cmd submission failed: %s\n",
			devname, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		err(ctx, "%s: firmware status: %d:\n%s\n",
			devname, rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (op == LSA_OP_GET)
		memcpy(*buf, cxl_cmd_get_lsa_get_payload(cmd), length);
	/*
	 * TODO: If writing, the memdev may need to be disabled/re-enabled to
	 * refresh any cached LSA data in the kernel.
	 */

out:
	cxl_cmd_unref(cmd);
out_free:
	free(zero_buf);
	return rc;
}

CXL_EXPORT int cxl_memdev_zero_lsa(struct cxl_memdev *memdev)
{
	return lsa_op(memdev, LSA_OP_ZERO, NULL, 0, 0);
}

CXL_EXPORT int cxl_memdev_set_lsa(struct cxl_memdev *memdev, void *buf,
		size_t length, size_t offset)
{
	return lsa_op(memdev, LSA_OP_SET, &buf, length, offset);
}

CXL_EXPORT int cxl_memdev_get_lsa(struct cxl_memdev *memdev, void *buf,
		size_t length, size_t offset)
{
	return lsa_op(memdev, LSA_OP_GET, &buf, length, offset);
}

CXL_EXPORT int cxl_memdev_cmd_identify(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_cmd_identify *id;
	int rc = 0;

	printf("id: 0x%x\n", CXL_MEM_COMMAND_ID_IDENTIFY);
	cmd = cxl_cmd_new_identify(memdev);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_identify returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	id = (void *)cmd->send_cmd->out.payload;
	fprintf(stderr, "size of payload: %ld\n", sizeof(*id));
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_IDENTIFY) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_IDENTIFY);
		return -EINVAL;
	}

	fprintf(stdout, "%s info\n", cxl_memdev_get_devname(memdev));
	fprintf(stdout, "    fw revision: ");
	for (int i=0; i < CXL_CMD_IDENTIFY_FW_REV_LENGTH; ++i)
		fprintf(stdout, "%02x ", id->fw_revision[i]);
	fprintf(stdout, "\n");
	fprintf(stdout, "    total_capacity: %lu MB (%lu GB)\n",
	le64_to_cpu(id->total_capacity), (le64_to_cpu(id->total_capacity))/4);
	fprintf(stdout, "    volatile_capacity: %lu MB (%lu GB)\n",
	le64_to_cpu(id->volatile_capacity), (le64_to_cpu(id->volatile_capacity))/4);
	fprintf(stdout, "    persistent_capacity: %lu MB (%lu GB)\n",
	le64_to_cpu(id->persistent_capacity), (le64_to_cpu(id->persistent_capacity))/4);
	fprintf(stdout, "    partition_align: %lu MB (%lu GB)\n",
	le64_to_cpu(id->partition_align), (le64_to_cpu(id->partition_align))/4);
	fprintf(stdout, "    info_event_log_size: %d\n", le16_to_cpu(id->info_event_log_size));
	fprintf(stdout, "    warning_event_log_size: %d\n", le16_to_cpu(id->warning_event_log_size));
	fprintf(stdout, "    failure_event_log_size: %d\n", le16_to_cpu(id->failure_event_log_size));
	fprintf(stdout, "    fatal_event_log_size: %d\n", le16_to_cpu(id->fatal_event_log_size));
	fprintf(stdout, "    lsa_size: %d\n", le32_to_cpu(id->lsa_size));
	for (int i=0; i < 3; ++i)
	fprintf(stdout, "    poison_list_max_mer[%d]: %d\n", i, id->poison_list_max_mer[i]);
	fprintf(stdout, "    inject_poison_limit: %d\n", le16_to_cpu(id->inject_poison_limit));
	fprintf(stdout, "    poison_caps: %d\n", id->poison_caps);
	fprintf(stdout, "    qos_telemetry_caps: %d\n", id->qos_telemetry_caps);

out:
	cxl_cmd_unref(cmd);
	return rc;
}

struct cxl_mbox_get_supported_logs {
	__le16 entries;
	u8 rsvd[6];
	struct gsl_entry {
		uuid_t uuid;
		__le32 size;
	} __attribute__((packed)) entry[];
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_supported_logs(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_get_supported_logs *gsl;
	int rc = 0;

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_GET_SUPPORTED_LOGS);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_identify returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_SUPPORTED_LOGS) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev),
				cmd->send_cmd->id,
				CXL_MEM_COMMAND_ID_GET_SUPPORTED_LOGS);
		return -EINVAL;
	}

	gsl = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "payload info\n");
	fprintf(stdout, "    out size: 0x%x\n", cmd->send_cmd->out.size);
	fprintf(stdout, "    entries: %d\n", gsl->entries);
	for (int e=0; e < gsl->entries; ++e) {
		char uuid[40];
		uuid_unparse(gsl->entry[e].uuid, uuid);
		fprintf(stdout, "        entries[%d] uuid: %s, size: %d\n", e, uuid, gsl->entry[e].size);
	}
out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CEL_UUID "0da9c0b5-bf41-4b78-8f79-96b1623b3f17"

struct cxl_mbox_get_log {
	uuid_t uuid;
	__le32 offset;
	__le32 length;
}  __attribute__((packed));

struct cel_entry {
	__le16 opcode;
	__le16 effect;
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_cel_log(struct cxl_memdev *memdev, const char* uuid)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_get_log *get_log_input;
	struct cel_entry *cel_entries;
	int no_cel_entries;
	int rc = 0;

	if (!uuid) {
		fprintf(stderr, "%s: Please specify log uuid argument\n",
				cxl_memdev_get_devname(memdev));
		return -EINVAL;
	}

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_GET_LOG);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_memdev_get_cel_log returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	get_log_input = (void *) cmd->send_cmd->in.payload;
	uuid_parse(uuid, get_log_input->uuid);
	get_log_input->offset = 0;
	get_log_input->length = cmd->memdev->payload_max;

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_LOG) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_LOG);
		return -EINVAL;
	}

	fprintf(stdout, "payload info\n");
	fprintf(stdout, "    out size: 0x%x\n", cmd->send_cmd->out.size);
	cel_entries = (void *)cmd->send_cmd->out.payload;
	no_cel_entries = (cmd->send_cmd->out.size)/sizeof(struct cel_entry);
	fprintf(stdout, "    no_cel_entries size: %d\n", no_cel_entries);
	for (int e = 0; e < no_cel_entries; ++e) {
		fprintf(stdout, "    cel_entry[%d] opcode: 0x%x, effect: 0x%x\n", e,
				le16_to_cpu(cel_entries[e].opcode),
				le16_to_cpu(cel_entries[e].effect));
	}
out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY_OPCODE 0x102

struct cxl_mbox_get_event_interrupt_policy {
	u8 info_event_log_int_settings;
	u8 warning_event_log_int_settings;
	u8 failure_event_log_int_settings;
	u8 fatal_event_log_int_settings;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_event_interrupt_policy(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_get_event_interrupt_policy *event_interrupt_policy_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY);
		return -EINVAL;
	}

	fprintf(stdout, "payload info\n");
	fprintf(stdout, "    out size: 0x%x\n", cmd->send_cmd->out.size);
	event_interrupt_policy_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "    info_event_log_int_settings: 0x%x\n", event_interrupt_policy_out->info_event_log_int_settings);
	fprintf(stdout, "    warning_event_log_int_settings: 0x%x\n", event_interrupt_policy_out->warning_event_log_int_settings);
	fprintf(stdout, "    failure_event_log_int_settings: 0x%x\n", event_interrupt_policy_out->failure_event_log_int_settings);
	fprintf(stdout, "    fatal_event_log_int_settings: 0x%x\n", event_interrupt_policy_out->fatal_event_log_int_settings);
out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY_OPCODE 0x103
#define CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY_PAYLOAD_IN_SIZE 0x4

CXL_EXPORT int cxl_memdev_set_event_interrupt_policy(struct cxl_memdev *memdev, u32 int_policy)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
    struct cxl_command_info *cinfo;
	struct cxl_mbox_get_event_interrupt_policy *interrupt_policy_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* this is hack to create right payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
        cmd->input_payload = calloc(1, cinfo->size_in);
        if (!cmd->input_payload)
            return -ENOMEM;
        cmd->send_cmd->in.payload = (u64)cmd->input_payload;
        cmd->send_cmd->in.size = cinfo->size_in;
    }

	interrupt_policy_in = (void *) cmd->send_cmd->in.payload;

	/* below is meant for readability, you don't really need this */
	int_policy = cpu_to_be32(int_policy);
	interrupt_policy_in->info_event_log_int_settings = (int_policy & 0xff);
	interrupt_policy_in->warning_event_log_int_settings = ((int_policy >> 8) & 0xff);
	interrupt_policy_in->failure_event_log_int_settings = ((int_policy >> 16) & 0xff);
	interrupt_policy_in->fatal_event_log_int_settings = ((int_policy >> 24) & 0xff);

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_SET_EVENT_INTERRUPT_POLICY);
		return -EINVAL;
	}

	fprintf(stdout, "command completed successfully\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_GET_TIMESTAMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_GET_TIMESTAMP_OPCODE 0x0300

CXL_EXPORT int cxl_memdev_get_timestamp(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	__le64 *timestamp_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_GET_TIMESTAMP_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_TIMESTAMP) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_TIMESTAMP);
		return -EINVAL;
	}

	timestamp_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "timestamp: 0x%lx\n", le64_to_cpu(*timestamp_out));
out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CXL_MEM_COMMAND_ID_SET_TIMESTAMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_SET_TIMESTAMP_OPCODE 0x0301
#define CXL_MEM_COMMAND_ID_SET_TIMESTAMP_PAYLOAD_IN_SIZE 8

CXL_EXPORT int cxl_memdev_set_timestamp(struct cxl_memdev *memdev, u64 timestamp)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
    struct cxl_command_info *cinfo;
	__le64 *timestamp_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_SET_TIMESTAMP_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}
	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* this is hack to create right payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_SET_TIMESTAMP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
        cmd->input_payload = calloc(1, cinfo->size_in);
        if (!cmd->input_payload)
            return -ENOMEM;
        cmd->send_cmd->in.payload = (u64)cmd->input_payload;
        cmd->send_cmd->in.size = cinfo->size_in;
    }

	timestamp_in = (void *) cmd->send_cmd->in.payload;
	*timestamp_in = cpu_to_le64(timestamp);
	fprintf(stdout, "setting timestamp to: 0x%lx\n", le64_to_cpu(*timestamp_in));

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_SET_TIMESTAMP) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_SET_TIMESTAMP);
		return -EINVAL;
	}

	fprintf(stdout, "command completed successfully\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
}

struct cxl_mbox_get_alert_config_out {
	u8 valid_alerts;
	u8 programmable_alerts;
	u8 life_used_critical_alert_threshold;
	u8 life_used_prog_warn_threshold;
	__le16 dev_over_temp_crit_alert_threshold;
	__le16 dev_under_temp_crit_alert_threshold;
	__le16 dev_over_temp_prog_warn_threshold;
	__le16 dev_under_temp_prog_warn_threshold;
	__le16 corr_vol_mem_err_prog_warn_thresold;
	__le16 corr_pers_mem_err_prog_warn_threshold;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_alert_config(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_get_alert_config_out *alert_config_out;
	int rc = 0;

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_GET_ALERT_CONFIG);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_ALERT_CONFIG) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_ALERT_CONFIG);
		return -EINVAL;
	}

	fprintf(stdout, "alert_config summary\n");
	//fprintf(stdout, "    out size: 0x%x\n", cmd->send_cmd->out.size);

	alert_config_out = (void *)cmd->send_cmd->out.payload;

	fprintf(stdout, "    valid_alerts: 0x%x\n", alert_config_out->valid_alerts);
	fprintf(stdout, "    programmable_alerts: 0x%x\n", alert_config_out->programmable_alerts);
	fprintf(stdout, "    life_used_critical_alert_threshold: 0x%x\n",
		alert_config_out->life_used_critical_alert_threshold);
	fprintf(stdout, "    life_used_prog_warn_threshold: 0x%x\n",
		alert_config_out->life_used_prog_warn_threshold);

	fprintf(stdout, "    dev_over_temp_crit_alert_threshold: 0x%x\n",
		le16_to_cpu(alert_config_out->dev_over_temp_crit_alert_threshold));
	fprintf(stdout, "    dev_under_temp_crit_alert_threshold: 0x%x\n",
		le16_to_cpu(alert_config_out->dev_under_temp_crit_alert_threshold));
	fprintf(stdout, "    dev_over_temp_prog_warn_threshold: 0x%x\n",
		le16_to_cpu(alert_config_out->dev_over_temp_prog_warn_threshold));
	fprintf(stdout, "    dev_under_temp_prog_warn_threshold: 0x%x\n",
		le16_to_cpu(alert_config_out->dev_under_temp_prog_warn_threshold));
	fprintf(stdout, "    corr_vol_mem_err_prog_warn_thresold: 0x%x\n",
		le16_to_cpu(alert_config_out->corr_vol_mem_err_prog_warn_thresold));
	fprintf(stdout, "    corr_pers_mem_err_prog_warn_threshold: 0x%x\n",
		le16_to_cpu(alert_config_out->corr_pers_mem_err_prog_warn_threshold));

out:
	cxl_cmd_unref(cmd);
	return rc;
}

struct cxl_mbox_set_alert_config_in {
    u8 valid_alert_actions;
    u8 enable_alert_actions;
    u8 life_used_prog_warn_threshold;
    u8 reserved;
    __le16 dev_over_temp_prog_warn_threshold;
    __le16 dev_under_temp_prog_warn_threshold;
    __le16 corr_vol_mem_err_prog_warn_thresold;
    __le16 corr_pers_mem_err_prog_warn_threshold;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_set_alert_config(struct cxl_memdev *memdev, u32 alert_prog_threshold,
	u32 device_temp_threshold, u32 mem_error_threshold)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_set_alert_config_in *alert_config_in;
	int rc = 0;

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_SET_ALERT_CONFIG);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	alert_config_in = (void *) cmd->send_cmd->in.payload;

	alert_prog_threshold = cpu_to_be32(alert_prog_threshold);
	device_temp_threshold = cpu_to_be32(device_temp_threshold);
	mem_error_threshold = cpu_to_be32(mem_error_threshold);

	alert_config_in->valid_alert_actions = ((alert_prog_threshold >> 8) & 0xff);
	alert_config_in->enable_alert_actions = ((alert_prog_threshold >> 16) & 0xff);
	alert_config_in->life_used_prog_warn_threshold = ((alert_prog_threshold >> 24) & 0xff);
	alert_config_in->reserved = 0;

	alert_config_in->dev_over_temp_prog_warn_threshold = cpu_to_le16(be16_to_cpu(((device_temp_threshold) & 0xffff)));
	alert_config_in->dev_under_temp_prog_warn_threshold = cpu_to_le16(be16_to_cpu((((device_temp_threshold) >> 16) & 0xffff)));

	alert_config_in->corr_vol_mem_err_prog_warn_thresold = cpu_to_le16(be16_to_cpu((mem_error_threshold & 0xffff)));
	alert_config_in->corr_pers_mem_err_prog_warn_threshold = cpu_to_le16(be16_to_cpu(((mem_error_threshold >> 16) & 0xffff)));

	fprintf(stdout, "alert_config settings\n");
	fprintf(stdout, "    valid_alert_actions: 0x%x\n", alert_config_in->valid_alert_actions);
	fprintf(stdout, "    enable_alert_actions: 0x%x\n", alert_config_in->enable_alert_actions);
	fprintf(stdout, "    life_used_prog_warn_threshold: 0x%x\n", alert_config_in->life_used_prog_warn_threshold);
	fprintf(stdout, "    dev_over_temp_prog_warn_threshold: 0x%x\n",
		le16_to_cpu(alert_config_in->dev_over_temp_prog_warn_threshold));
	fprintf(stdout, "    dev_under_temp_prog_warn_threshold: 0x%x\n",
		le16_to_cpu(alert_config_in->dev_under_temp_prog_warn_threshold));
	fprintf(stdout, "    corr_vol_mem_err_prog_warn_thresold: 0x%x\n",
		le16_to_cpu(alert_config_in->corr_vol_mem_err_prog_warn_thresold));
	fprintf(stdout, "    corr_pers_mem_err_prog_warn_threshold: 0x%x\n",
		le16_to_cpu(alert_config_in->corr_pers_mem_err_prog_warn_threshold));

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_SET_ALERT_CONFIG) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_SET_ALERT_CONFIG);
		return -EINVAL;
	}

	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
}

struct cxl_health_info {
    u8 health_state;
    u8 media_status;
    u8 additional_status;
    u8 life_used;
    __le16 device_temp;
    __le32 dirty_shutdown_count;
    __le32 corr_vol_mem_err_count;
    __le32 corr_pers_mem_err_count;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_health_info(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_health_info *health_info;
	int rc = 0;

	cmd = cxl_cmd_new_generic(memdev, CXL_MEM_COMMAND_ID_GET_HEALTH_INFO);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_memdev_get_health_info returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_HEALTH_INFO) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_HEALTH_INFO);
		return -EINVAL;
	}

	if (cmd->send_cmd->out.size != sizeof(*health_info)) {
		fprintf(stderr, "%s: invalid payload output size (got: %d, required: %ld)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->out.size, sizeof(*health_info));
		return -EINVAL;
	}

	health_info = (void *)cmd->send_cmd->out.payload;

	fprintf(stdout, "Device Health Info\n");
	fprintf(stdout, "    out size: 0x%x\n", cmd->send_cmd->out.size);
	fprintf(stdout, "    health_state: 0x%x\n", health_info->health_state);
	fprintf(stdout, "    media_status: 0x%x\n", health_info->media_status);
	fprintf(stdout, "    additional_status: 0x%x\n", health_info->additional_status);
	fprintf(stdout, "    life_used: 0x%x\n", health_info->life_used);
	fprintf(stdout, "    device_temp: 0x%x\n", le16_to_cpu(health_info->device_temp));
	fprintf(stdout, "    dirty_shutdown_count: 0x%x\n", le32_to_cpu(health_info->dirty_shutdown_count));
	fprintf(stdout, "    corr_vol_mem_err_count: 0x%x\n", le32_to_cpu(health_info->corr_vol_mem_err_count));
	fprintf(stdout, "    corr_pers_mem_err_count: 0x%x\n", le32_to_cpu(health_info->corr_pers_mem_err_count));
out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS_OPCODE 0x100
#define CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS_PAYLOAD_IN_SIZE 0x1
#define CXL_MAX_RECORDS_TO_DUMP 20

#define CXL_DRAM_EVENT_GUID "601dcbb3-9c06-4eab-b8af-4e9bfb5c9624"
#define CXL_MEM_MODULE_EVENT_GUID "fe927475-dd59-4339-a586-79bab113b774"

struct cxl_dram_event_record {
	__le64 physical_addr;
	u8 memory_event_descriptor;
	u8 memory_event_type;
	u8 transaction_type;
	__le16 validity_flags;
	u8 channel;
	u8 rank;
	u8 nibble_mask[3];
	u8 bank_group;
	u8 bank;
	u8 row[3];
	__le16 column;
	u8 correction_mask[0x20];
	u8 component_identifier[0x10];
	u8 sub_channel;
	u8 reserved[0x6];
} __attribute__((packed));

struct cxl_memory_module_record {
	u8 dev_event_type;
	u8 dev_health_info[0x12];
	u8 reserved[0x3d];
}__attribute__((packed));

struct cxl_event_record {
	uuid_t uuid;
	u8 event_record_length;
	u8 event_record_flags[3];
	__le16 event_record_handle;
	__le16 related_event_record_handle;
	__le64 event_record_ts;
	u8 reserved[0x10];
	union {
		struct cxl_dram_event_record dram_event_record;
		struct cxl_memory_module_record memory_module_record;
	} event_record;
} __attribute__((packed));

struct cxl_get_event_record_info {
    u8 flags;
    u8 reserved1;
    __le16 overflow_err_cnt;
    __le64 first_overflow_evt_ts;
    __le64 last_overflow_evt_ts;
    __le16 event_record_count;
	u8 reserved2[0xa];
	struct cxl_event_record event_records[];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_event_records(struct cxl_memdev *memdev, u8 event_log_type)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
    struct cxl_command_info *cinfo;
	struct cxl_get_event_record_info *event_info;
	int rc = 0;
	int rec;
	int indent = 2;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* this is hack to create right payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
        cmd->input_payload = calloc(1, cinfo->size_in);
        if (!cmd->input_payload)
            return -ENOMEM;
        cmd->send_cmd->in.payload = (u64)cmd->input_payload;
        cmd->send_cmd->in.size = cinfo->size_in;
    }

	* ((u8 *) cmd->send_cmd->in.payload) = event_log_type;

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_EVENT_RECORDS);
		return -EINVAL;
	}

	event_info = (void *)cmd->send_cmd->out.payload;

	fprintf(stdout, "cxl_dram_event_record size: 0x%lx\n", sizeof(struct cxl_dram_event_record));
	fprintf(stdout, "cxl_memory_module_record size: 0x%lx\n", sizeof(struct cxl_memory_module_record));
	fprintf(stdout, "cxl_event_record size: 0x%lx\n", sizeof(struct cxl_event_record));
	fprintf(stdout, "cxl_get_event_record_info size: 0x%lx\n", sizeof(struct cxl_get_event_record_info));
	fprintf(stdout, "========= Get Event Records Info =========\n");
	fprintf(stdout, "%*sout size: 0x%x\n", indent, "", cmd->send_cmd->out.size);
	fprintf(stdout, "%*sflags: 0x%x\n", indent, "", event_info->flags);
	fprintf(stdout, "%*soverflow_err_cnt: 0x%x\n", indent, "", le16_to_cpu(event_info->overflow_err_cnt));
	fprintf(stdout, "%*sfirst_overflow_evt_ts: 0x%lx\n", indent, "", le64_to_cpu(event_info->first_overflow_evt_ts));
	fprintf(stdout, "%*slast_overflow_evt_ts: 0x%lx\n", indent, "", le64_to_cpu(event_info->last_overflow_evt_ts));
	fprintf(stdout, "%*sevent_record_count: 0x%x\n", indent, "", le16_to_cpu(event_info->event_record_count));

	for (rec = 0; rec < min(CXL_MAX_RECORDS_TO_DUMP, le16_to_cpu(event_info->event_record_count)); ++rec) {
		char uuid[40];
		struct cxl_event_record *event_record = &event_info->event_records[rec];

		uuid_unparse(event_info->event_records[rec].uuid, uuid);

		if (strcmp(uuid, CXL_DRAM_EVENT_GUID) == 0)
			fprintf(stdout, "%*sEvent Record: %d (DRAM guid: %s)\n", indent, "", rec, uuid);
		else if (strcmp(uuid, CXL_MEM_MODULE_EVENT_GUID) == 0)
			fprintf(stdout, "%*sEvent Record: %d (Memory Module Event guid: %s)\n", indent, "", rec, uuid);
		else
			fprintf(stdout, "%*sEvent Record: %d (uuid: %s)\n", indent, "", rec, uuid);

		fprintf(stdout, "%*sevent_record_length: 0x%x\n", indent+2, "", event_record->event_record_length);
		fprintf(stdout, "%*sevent_record_flags: 0x%02x%02x%02x\n", indent+2, "", event_record->event_record_flags[0],
			event_record->event_record_flags[1], event_record->event_record_flags[2]);
		fprintf(stdout, "%*sevent_record_handle: 0x%x\n", indent+2, "", le16_to_cpu(event_record->event_record_handle));
		fprintf(stdout, "%*srelated_event_record_handle: 0x%x\n", indent+2, "",
			le16_to_cpu(event_record->related_event_record_handle));
		fprintf(stdout, "%*sevent_record_ts: 0x%lx\n", indent+2, "", le64_to_cpu(event_record->event_record_ts));

		if (strcmp(uuid, CXL_DRAM_EVENT_GUID) == 0){
			struct cxl_dram_event_record *dram_event = &event_record->event_record.dram_event_record;
			fprintf(stdout, "%*sphysical_addr: 0x%lx\n", indent+2, "", le64_to_cpu(dram_event->physical_addr));
			fprintf(stdout, "%*smemory_event_descriptor: 0x%x\n", indent+2, "", dram_event->memory_event_descriptor);
			fprintf(stdout, "%*smemory_event_type: 0x%x\n", indent+2, "", dram_event->memory_event_type);
			fprintf(stdout, "%*stransaction_type: 0x%x\n", indent+2, "", dram_event->transaction_type);
			fprintf(stdout, "%*svalidity_flags: 0x%x\n", indent+2, "", le16_to_cpu(dram_event->validity_flags));
			fprintf(stdout, "%*schannel: 0x%x\n", indent+2, "", dram_event->channel);
			fprintf(stdout, "%*srank: 0x%x\n", indent+2, "", dram_event->rank);
			fprintf(stdout, "%*snibble_mask: 0x%02x%02x%02x\n", indent+2, "",
				dram_event->nibble_mask[0], dram_event->nibble_mask[1],
				dram_event->nibble_mask[2]);
			fprintf(stdout, "%*sbank_group: 0x%x\n", indent+2, "", dram_event->bank_group);
			fprintf(stdout, "%*sbank: 0x%x\n", indent+2, "", dram_event->bank);
			fprintf(stdout, "%*srow: 0x%02x%02x%02x\n", indent+2, "", dram_event->row[0],
				dram_event->row[1], dram_event->row[2]);
			fprintf(stdout, "%*scolumn: 0x%x\n", indent+2, "", le16_to_cpu(dram_event->column));
			for (int i=0; i < 4; i++) {
				fprintf(stdout, "%*scorrection mask[%d]: 0x", indent+2, "", i);
				for (int j=0; j < 8; j++) {
					fprintf(stdout, "%02x", dram_event->correction_mask[i*j+j]);
				}
				fprintf(stdout, "\n");
			}
			fprintf(stdout, "%*scomponent identifier: 0x%02x%02x%02x\n", indent+2, "",
				dram_event->component_identifier[0], dram_event->component_identifier[1],
				dram_event->component_identifier[2]);
		}
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

// GET_LD_INFO START
#define CXL_MEM_COMMAND_ID_GET_LD_INFO CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_GET_LD_INFO_OPCODE 0x5400
#define CXL_MEM_COMMAND_ID_GET_LD_INFO_PAYLOAD_OUT_SIZE 0xb

struct cxl_get_ld_info {
	__le64 mem_size;
	__le16 ld_cnt;
	u8 qos_telemetry_capa;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_ld_info(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_get_ld_info *ld_info;
	int rc = 0;
	int indent = 2;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_GET_LD_INFO_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}
	cmd->send_cmd->in.size = 0;

	fprintf(stdout, "Getting LD info for memdev %s\n", cxl_memdev_get_devname(memdev));

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_LD_INFO) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_LD_INFO);
		return -EINVAL;
	}

	ld_info = (void *)cmd->send_cmd->out.payload;

	fprintf(stdout, "========= Get LD Info =========\n");
	fprintf(stdout, "%*sout size: 0x%x\n", indent, "", cmd->send_cmd->out.size);
	fprintf(stdout, "%*smemory size: 0x%lx\n", indent, "", le64_to_cpu(ld_info->mem_size));
	fprintf(stdout, "%*sld count: 0x%x\n", indent, "", le16_to_cpu(ld_info->ld_cnt));
	fprintf(stdout, "%*sqos telemetry capability: 0x%x\n", indent, "", ld_info->qos_telemetry_capa);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

// GET_LD_INFO END

#define CXL_MEM_COMMAND_ID_DEVICE_INFO_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_DEVICE_INFO_GET_OPCODE 49152
#define CXL_MEM_COMMAND_ID_DEVICE_INFO_GET_PAYLOAD_OUT_SIZE 8
#define CXL_MEM_COMMAND_ID_DEVICE_INFO_GET_PAYLOAD_IN_SIZE 0


struct cxl_mbox_device_info_get_out {
	__le16 device_id;
	u8 chipinfo_rel_major;
	u8 chipinfo_rel_minor;
	u8 device_rev;
	u8 configfile_ver_major;
	__le16 configfile_ver_minor;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_device_info_get(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_device_info_get_out *device_info_get_out;
	int rc = 0;
	char release_major;
	release_major = 'A';

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_DEVICE_INFO_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* this is hack to create right payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_DEVICE_INFO_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_DEVICE_INFO_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_DEVICE_INFO_GET);
		return -EINVAL;
	}

	device_info_get_out = (void *)cmd->send_cmd->out.payload;
	release_major = release_major + device_info_get_out->chipinfo_rel_major;
	fprintf(stdout, "=========================== read device information ============================\n");

	fprintf(stdout, "Release & Revision for Device ID %x: %c.%x Rev %x\n",
				device_info_get_out->device_id,
				release_major,
				device_info_get_out->chipinfo_rel_minor,
				device_info_get_out->device_rev);
	fprintf(stdout, "Device ID: %x\n", device_info_get_out->device_id);
	fprintf(stdout, "Chip Info Release Major: %x\n", device_info_get_out->chipinfo_rel_major);
	fprintf(stdout, "Chip Info Release Minor: %x\n", device_info_get_out->chipinfo_rel_minor);
	fprintf(stdout, "Device Revision: %x\n", device_info_get_out->device_rev);
	fprintf(stdout, "ConfigFile version Major: %x\n", device_info_get_out->configfile_ver_major);
	fprintf(stdout, "ConfigFile version Minor: %x\n", device_info_get_out->configfile_ver_minor);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_GET_FW_INFO CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_GET_FW_INFO_OPCODE 512
#define CXL_MEM_COMMAND_ID_GET_FW_INFO_PAYLOAD_OUT_SIZE 80


struct cxl_mbox_get_fw_info_out {
	u8 fw_slots_supp;
	u8 fw_slot_info;
	u8 fw_activation_capas;
	u8 rsvd[13];
	char slot_1_fw_rev[16];
	char slot_2_fw_rev[16];
	char slot_3_fw_rev[16];
	char slot_4_fw_rev[16];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_get_fw_info(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_get_fw_info_out *get_fw_info_out;
	int rc = 0;
	u8 active_slot_mask;
	u8 active_slot;
	u8 staged_slot_mask;
	u8 staged_slot;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_GET_FW_INFO_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_GET_FW_INFO) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_GET_FW_INFO);
		return -EINVAL;
	}

	get_fw_info_out = (void *)cmd->send_cmd->out.payload;
	active_slot_mask = 0b00000111;
	active_slot = get_fw_info_out->fw_slot_info & active_slot_mask;
	staged_slot_mask = 0b00111000;
	staged_slot = get_fw_info_out->fw_slot_info & staged_slot_mask;
	staged_slot = staged_slot>>3;
	fprintf(stdout, "================================= get fw info ==================================\n");
	fprintf(stdout, "FW Slots Supported: %x\n", get_fw_info_out->fw_slots_supp);
	fprintf(stdout, "Active FW Slot: %x\n", active_slot);
	if (staged_slot)
	{
		fprintf(stdout, "Staged FW Slot: %x\n", staged_slot);
	}
	fprintf(stdout, "FW Activation Capabilities: %x\n", get_fw_info_out->fw_activation_capas);
	fprintf(stdout, "Slot 1 FW Revision: %s\n", get_fw_info_out->slot_1_fw_rev);
	fprintf(stdout, "Slot 2 FW Revision: %s\n", get_fw_info_out->slot_2_fw_rev);
	fprintf(stdout, "Slot 3 FW Revision: %s\n", get_fw_info_out->slot_3_fw_rev);
	fprintf(stdout, "Slot 4 FW Revision: %s\n", get_fw_info_out->slot_4_fw_rev);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_TRANSFER_FW CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_TRANSFER_FW_PAYLOAD_IN_SIZE 128 + FW_BLOCK_SIZE

struct cxl_mbox_transfer_fw_in {
	u8 action;
	u8 slot;
	__le16 rsvd;
	__le32 offset;
	__le64 rsvd8[15];
	fwblock data;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_transfer_fw(struct cxl_memdev *memdev,
	u8 action, u8 slot, u32 offset, int size,
    unsigned char *data, u32 transfer_fw_opcode)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_transfer_fw_in *transfer_fw_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, transfer_fw_opcode);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* used to force correct payload size */
	cinfo->size_in = 128 + size;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	transfer_fw_in = (struct cxl_mbox_transfer_fw_in *) cmd->send_cmd->in.payload;
	transfer_fw_in->action = action;
	transfer_fw_in->slot = slot;
	transfer_fw_in->offset = cpu_to_le32(offset);
	memcpy(transfer_fw_in->data, data, size);

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_TRANSFER_FW) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_TRANSFER_FW);
		rc = -EINVAL;
		goto out;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_ACTIVATE_FW CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ACTIVATE_FW_OPCODE 52482
#define CXL_MEM_COMMAND_ID_ACTIVATE_FW_PAYLOAD_IN_SIZE 2

struct cxl_mbox_activate_fw_in {
	u8 action;
	u8 slot;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_activate_fw(struct cxl_memdev *memdev,
	u8 action, u8 slot)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_activate_fw_in *activate_fw_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_ACTIVATE_FW_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* this is hack to create right payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_ACTIVATE_FW_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	activate_fw_in = (void *) cmd->send_cmd->in.payload;

	activate_fw_in->action = action;
	activate_fw_in->slot = slot;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ACTIVATE_FW) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_ACTIVATE_FW);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_DDR_INFO CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_DDR_INFO_OPCODE 50432
#define CXL_MEM_COMMAND_ID_DDR_INFO_PAYLOAD_IN_SIZE 1
#define CXL_MEM_COMMAND_ID_DDR_INFO_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_ddr_info_in {
	u8 ddr_id;
}  __attribute__((packed));

struct cxl_mbox_ddr_info_out {
	__le32 mstr_reg;
	__le32 dram_width;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_ddr_info(struct cxl_memdev *memdev, u8 ddr_id)
{
	/*const char *dram_width_descriptions[4] = {
		"DRAM Width x4 device",
		"DRAM Width x8 device",
		"DRAM Width x16 device",
		"DRAM Width x32 device"
	};*/

	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ddr_info_in *ddr_info_in;
	struct cxl_mbox_ddr_info_out *ddr_info_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_DDR_INFO_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_DDR_INFO_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ddr_info_in = (void *) cmd->send_cmd->in.payload;

	ddr_info_in->ddr_id = ddr_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_DDR_INFO) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_DDR_INFO);
		return -EINVAL;
	}

	ddr_info_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=================================== ddr info ===================================\n");
	fprintf(stdout, "DDR controller MSTR register: %x\n", le32_to_cpu(ddr_info_out->mstr_reg));
	fprintf(stdout, "DRAM width derived from DEVICE_CONFIG: %d\n", le32_to_cpu(ddr_info_out->dram_width));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_CLEAR_EVENT_RECORDS CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_CLEAR_EVENT_RECORDS_OPCODE 0x101

struct cxl_clear_event_record_info {
    u8 event_log_type;
    u8 clear_event_flags;
    u8 no_event_record_handles;
	u8 reserved[3];
	__le16 event_record_handles[];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_clear_event_records(struct cxl_memdev *memdev, u8 event_log_type,
	u8 clear_event_flags, u8 no_event_record_handles, u16 *event_record_handles)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
    struct cxl_command_info *cinfo;
	struct cxl_clear_event_record_info *event_info;
	int rc = 0;
	int rec;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_CLEAR_EVENT_RECORDS_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* this is hack to create right payload size */
	cinfo->size_in = sizeof(*event_info) + (no_event_record_handles * sizeof(__le16));
	if (cinfo->size_in > 0) {
        cmd->input_payload = calloc(1, cinfo->size_in);
        if (!cmd->input_payload)
            return -ENOMEM;
        cmd->send_cmd->in.payload = (u64)cmd->input_payload;
        cmd->send_cmd->in.size = cinfo->size_in;
    }

	if (clear_event_flags) {
		dbg(memdev->ctx, "Clearing 'All Event' Records for type %d\n", event_log_type);
	}

	event_info = (struct cxl_clear_event_record_info *) cmd->send_cmd->in.payload;
	event_info->event_log_type = event_log_type;
	event_info->clear_event_flags = clear_event_flags;
	event_info->no_event_record_handles = no_event_record_handles;
	for (rec = 0; rec < event_info->no_event_record_handles; ++rec) {
		dbg(memdev->ctx, "Clearing Event Record 0x%x for %d type\n", event_record_handles[rec], event_log_type);
		event_info->event_record_handles[rec] = cpu_to_le16(event_record_handles[rec]);
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_CLEAR_EVENT_RECORDS) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_CLEAR_EVENT_RECORDS);
		return -EINVAL;
	}

	fprintf(stdout, "Clear Event Records command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER_OPCODE 50691
#define CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER_PAYLOAD_IN_SIZE 2

struct cxl_mbox_hct_start_stop_trigger_in {
	u8 hct_inst;
	u8 buf_control;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_hct_start_stop_trigger(struct cxl_memdev *memdev,
	u8 hct_inst, u8 buf_control)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_hct_start_stop_trigger_in *hct_start_stop_trigger_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	hct_start_stop_trigger_in = (void *) cmd->send_cmd->in.payload;

	hct_start_stop_trigger_in->hct_inst = hct_inst;
	hct_start_stop_trigger_in->buf_control = buf_control;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_START_STOP_TRIGGER);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS_OPCODE 50692
#define CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS_PAYLOAD_IN_SIZE 1
#define CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS_PAYLOAD_OUT_SIZE 2

struct cxl_mbox_hct_get_buffer_status_in {
	u8 hct_inst;
}  __attribute__((packed));

struct cxl_mbox_hct_get_buffer_status_out {
	u8 buf_status;
	u8 fill_level;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_hct_get_buffer_status(struct cxl_memdev *memdev,
	u8 hct_inst)
{
	const char *buf_status_descriptions[] = {
		"Stop",
		"Pre-Trigger",
		"Post-Trigger"
	};

	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_hct_get_buffer_status_in *hct_get_buffer_status_in;
	struct cxl_mbox_hct_get_buffer_status_out *hct_get_buffer_status_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	hct_get_buffer_status_in = (void *) cmd->send_cmd->in.payload;

	hct_get_buffer_status_in->hct_inst = hct_inst;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_GET_BUFFER_STATUS);
		return -EINVAL;
	}

	hct_get_buffer_status_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "======================= get hif/cxl trace buffer status ========================\n");
	fprintf(stdout, "Buffer Status: %s\n", buf_status_descriptions[hct_get_buffer_status_out->buf_status]);
	fprintf(stdout, "Fill Level: %x\n", hct_get_buffer_status_out->fill_level);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HCT_ENABLE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_ENABLE_OPCODE 50694
#define CXL_MEM_COMMAND_ID_HCT_ENABLE_PAYLOAD_IN_SIZE 1

struct cxl_mbox_hct_enable_in {
	u8 hct_inst;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_hct_enable(struct cxl_memdev *memdev,
	u8 hct_inst)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_hct_enable_in *hct_enable_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_ENABLE_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_HCT_ENABLE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	hct_enable_in = (void *) cmd->send_cmd->in.payload;

	hct_enable_in->hct_inst = hct_inst;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_ENABLE) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_ENABLE);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR_OPCODE 50954
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR_PAYLOAD_IN_SIZE 2

struct cxl_mbox_ltmon_capture_clear_in {
	u8 rsvd;
	u8 cxl_mem_id;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_capture_clear(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_capture_clear_in *ltmon_capture_clear_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_capture_clear_in = (void *) cmd->send_cmd->in.payload;

	ltmon_capture_clear_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_CLEAR);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_OPCODE 50956
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_PAYLOAD_IN_SIZE 8

struct cxl_mbox_ltmon_capture_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 capt_mode;
	__le16 ignore_sub_chg;
	u8 ignore_rxl0_chg;
	u8 trig_src_sel;
	u8 rsvd7;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_capture(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 capt_mode, u16 ignore_sub_chg, u8 ignore_rxl0_chg,
	u8 trig_src_sel)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_capture_in *ltmon_capture_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_CAPTURE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_capture_in = (void *) cmd->send_cmd->in.payload;

	ltmon_capture_in->cxl_mem_id = cxl_mem_id;
	ltmon_capture_in->capt_mode = capt_mode;
	ltmon_capture_in->ignore_sub_chg = cpu_to_le16(ignore_sub_chg);
	ltmon_capture_in->ignore_rxl0_chg = ignore_rxl0_chg;
	ltmon_capture_in->trig_src_sel = trig_src_sel;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_CAPTURE) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_CAPTURE);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE_OPCODE 50958
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE_PAYLOAD_IN_SIZE 4

struct cxl_mbox_ltmon_capture_freeze_and_restore_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 freeze_restore;
	u8 rsvd3;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_capture_freeze_and_restore(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 freeze_restore)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_capture_freeze_and_restore_in *ltmon_capture_freeze_and_restore_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_capture_freeze_and_restore_in = (void *) cmd->send_cmd->in.payload;

	ltmon_capture_freeze_and_restore_in->cxl_mem_id = cxl_mem_id;
	ltmon_capture_freeze_and_restore_in->freeze_restore = freeze_restore;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_FREEZE_AND_RESTORE);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP_OPCODE 50960
#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP_PAYLOAD_IN_SIZE 2
#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP_PAYLOAD_OUT_SIZE 4

struct cxl_mbox_ltmon_l2r_count_dump_in {
	u8 rsvd;
	u8 cxl_mem_id;
}  __attribute__((packed));

struct cxl_mbox_ltmon_l2r_count_dump_out {
	__le32 dump_cnt;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_ltmon_l2r_count_dump(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_l2r_count_dump_in *ltmon_l2r_count_dump_in;
	struct cxl_mbox_ltmon_l2r_count_dump_out *ltmon_l2r_count_dump_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_l2r_count_dump_in = (void *) cmd->send_cmd->in.payload;

	ltmon_l2r_count_dump_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_DUMP);
		return -EINVAL;
	}

	ltmon_l2r_count_dump_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================= ltmon l2r count dump =============================\n");
	fprintf(stdout, "Dump Count: %x\n", le32_to_cpu(ltmon_l2r_count_dump_out->dump_cnt));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR_OPCODE 50961
#define CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR_PAYLOAD_IN_SIZE 2

struct cxl_mbox_ltmon_l2r_count_clear_in {
	u8 rsvd;
	u8 cxl_mem_id;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_l2r_count_clear(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_l2r_count_clear_in *ltmon_l2r_count_clear_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_l2r_count_clear_in = (void *) cmd->send_cmd->in.payload;

	ltmon_l2r_count_clear_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_L2R_COUNT_CLEAR);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG_OPCODE 50962
#define CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG_PAYLOAD_IN_SIZE 4

struct cxl_mbox_ltmon_basic_cfg_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 tick_cnt;
	u8 global_ts;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_basic_cfg(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 tick_cnt, u8 global_ts)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_basic_cfg_in *ltmon_basic_cfg_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_basic_cfg_in = (void *) cmd->send_cmd->in.payload;

	ltmon_basic_cfg_in->cxl_mem_id = cxl_mem_id;
	ltmon_basic_cfg_in->tick_cnt = tick_cnt;
	ltmon_basic_cfg_in->global_ts = global_ts;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_BASIC_CFG);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_WATCH CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_WATCH_OPCODE 50963
#define CXL_MEM_COMMAND_ID_LTMON_WATCH_PAYLOAD_IN_SIZE 12

struct cxl_mbox_ltmon_watch_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 watch_id;
	u8 watch_mode;
	u8 src_maj_st;
	u8 src_min_st;
	u8 src_l0_st;
	u8 dst_maj_st;
	u8 dst_min_st;
	u8 dst_l0_st;
	__le16 rsvd10;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_watch(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 watch_id, u8 watch_mode, u8 src_maj_st, u8 src_min_st,
	u8 src_l0_st, u8 dst_maj_st, u8 dst_min_st, u8 dst_l0_st)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_watch_in *ltmon_watch_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_WATCH_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_WATCH_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_watch_in = (void *) cmd->send_cmd->in.payload;

	ltmon_watch_in->cxl_mem_id = cxl_mem_id;
	ltmon_watch_in->watch_id = watch_id;
	ltmon_watch_in->watch_mode = watch_mode;
	ltmon_watch_in->src_maj_st = src_maj_st;
	ltmon_watch_in->src_min_st = src_min_st;
	ltmon_watch_in->src_l0_st = src_l0_st;
	ltmon_watch_in->dst_maj_st = dst_maj_st;
	ltmon_watch_in->dst_min_st = dst_min_st;
	ltmon_watch_in->dst_l0_st = dst_l0_st;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_WATCH) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_WATCH);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT_OPCODE 50964
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT_PAYLOAD_IN_SIZE 2
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT_PAYLOAD_OUT_SIZE 12

struct cxl_mbox_ltmon_capture_stat_in {
	u8 rsvd;
	u8 cxl_mem_id;
}  __attribute__((packed));

struct cxl_mbox_ltmon_capture_stat_out {
	__le16 trig_cnt;
	__le16 watch0_trig_cnt;
	__le16 watch1_trig_cnt;
	__le16 time_stamp;
	u8 trig_src_stat;
	u8 rsvd[3];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_ltmon_capture_stat(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_capture_stat_in *ltmon_capture_stat_in;
	struct cxl_mbox_ltmon_capture_stat_out *ltmon_capture_stat_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_capture_stat_in = (void *) cmd->send_cmd->in.payload;

	ltmon_capture_stat_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_STAT);
		return -EINVAL;
	}

	ltmon_capture_stat_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================= ltmon capture status =============================\n");
	fprintf(stdout, "Trigger Count: %x\n", le16_to_cpu(ltmon_capture_stat_out->trig_cnt));
	fprintf(stdout, "Watch 0 Trigger Count: %x\n", le16_to_cpu(ltmon_capture_stat_out->watch0_trig_cnt));
	fprintf(stdout, "Watch 1 Trigger Count: %x\n", le16_to_cpu(ltmon_capture_stat_out->watch1_trig_cnt));
	fprintf(stdout, "Time Stamp: %x\n", le16_to_cpu(ltmon_capture_stat_out->time_stamp));
	fprintf(stdout, "Trigger Source Status: %x\n", ltmon_capture_stat_out->trig_src_stat);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP_OPCODE 50965
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP_PAYLOAD_IN_SIZE 8
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP_PAYLOAD_OUT_SIZE 16

struct cxl_mbox_ltmon_capture_log_dmp_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 dump_idx;
	__le16 dump_cnt;
	__le16 rsvd6;
}  __attribute__((packed));

struct cxl_mbox_ltmon_capture_log_dmp_out {
	__le64 data[2];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_ltmon_capture_log_dmp(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u16 dump_idx, u16 dump_cnt)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_capture_log_dmp_in *ltmon_capture_log_dmp_in;
	struct cxl_mbox_ltmon_capture_log_dmp_out *ltmon_capture_log_dmp_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_capture_log_dmp_in = (void *) cmd->send_cmd->in.payload;

	ltmon_capture_log_dmp_in->cxl_mem_id = cxl_mem_id;
	ltmon_capture_log_dmp_in->dump_idx = cpu_to_le16(dump_idx);
	ltmon_capture_log_dmp_in->dump_cnt = cpu_to_le16(dump_cnt);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_LOG_DMP);
		return -EINVAL;
	}

	ltmon_capture_log_dmp_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================ ltmon capture log dump ============================\n");
	fprintf(stdout, "LTMON Data: ");
	/* Procedurally generated print statement. To print this array contiguously,
	   add "contiguous: True" to the YAML param and rerun cligen.py */
	for (int i = 0; i < 2; i++) {
		fprintf(stdout, "data[%d]: %lx\n", i, le64_to_cpu(ltmon_capture_log_dmp_out->data[i]));
	}
	fprintf(stdout, "\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER_OPCODE 50966
#define CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER_PAYLOAD_IN_SIZE 4

struct cxl_mbox_ltmon_capture_trigger_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 trig_src;
	u8 rsvd3;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_capture_trigger(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 trig_src)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_capture_trigger_in *ltmon_capture_trigger_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_capture_trigger_in = (void *) cmd->send_cmd->in.payload;

	ltmon_capture_trigger_in->cxl_mem_id = cxl_mem_id;
	ltmon_capture_trigger_in->trig_src = trig_src;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_CAPTURE_TRIGGER);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_LTMON_ENABLE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LTMON_ENABLE_OPCODE 51072
#define CXL_MEM_COMMAND_ID_LTMON_ENABLE_PAYLOAD_IN_SIZE 4

struct cxl_mbox_ltmon_enable_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 enable;
	u8 rsvd3;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_ltmon_enable(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 enable)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_ltmon_enable_in *ltmon_enable_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LTMON_ENABLE_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_LTMON_ENABLE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	ltmon_enable_in = (void *) cmd->send_cmd->in.payload;

	ltmon_enable_in->cxl_mem_id = cxl_mem_id;
	ltmon_enable_in->enable = enable;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LTMON_ENABLE) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LTMON_ENABLE);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG_OPCODE 51200
#define CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG_PAYLOAD_IN_SIZE 12

struct cxl_mbox_osa_os_type_trig_cfg_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
	__le16 lane_mask;
	u8 lane_dir_mask;
	u8 rate_mask;
	__le16 os_type_mask;
	__le16 rsvd10;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_osa_os_type_trig_cfg(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u16 lane_mask, u8 lane_dir_mask, u8 rate_mask, u16 os_type_mask)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_os_type_trig_cfg_in *osa_os_type_trig_cfg_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_os_type_trig_cfg_in = (void *) cmd->send_cmd->in.payload;

	osa_os_type_trig_cfg_in->cxl_mem_id = cxl_mem_id;
	osa_os_type_trig_cfg_in->lane_mask = cpu_to_le16(lane_mask);
	osa_os_type_trig_cfg_in->lane_dir_mask = lane_dir_mask;
	osa_os_type_trig_cfg_in->rate_mask = rate_mask;
	osa_os_type_trig_cfg_in->os_type_mask = cpu_to_le16(os_type_mask);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_OS_TYPE_TRIG_CFG);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_CAP_CTRL CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_CAP_CTRL_OPCODE 51203
#define CXL_MEM_COMMAND_ID_OSA_CAP_CTRL_PAYLOAD_IN_SIZE 16

struct cxl_mbox_osa_cap_ctrl_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
	__le16 lane_mask;
	u8 lane_dir_mask;
	u8 drop_single_os;
	u8 stop_mode;
	u8 snapshot_mode;
	__le16 post_trig_num;
	__le16 os_type_mask;
	__le16 rsvd14;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_osa_cap_ctrl(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u16 lane_mask, u8 lane_dir_mask, u8 drop_single_os,
	u8 stop_mode, u8 snapshot_mode, u16 post_trig_num, u16 os_type_mask)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_cap_ctrl_in *osa_cap_ctrl_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_CAP_CTRL_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_CAP_CTRL_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_cap_ctrl_in = (void *) cmd->send_cmd->in.payload;

	osa_cap_ctrl_in->cxl_mem_id = cxl_mem_id;
	osa_cap_ctrl_in->lane_mask = cpu_to_le16(lane_mask);
	osa_cap_ctrl_in->lane_dir_mask = lane_dir_mask;
	osa_cap_ctrl_in->drop_single_os = drop_single_os;
	osa_cap_ctrl_in->stop_mode = stop_mode;
	osa_cap_ctrl_in->snapshot_mode = snapshot_mode;
	osa_cap_ctrl_in->post_trig_num = cpu_to_le16(post_trig_num);
	osa_cap_ctrl_in->os_type_mask = cpu_to_le16(os_type_mask);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_CAP_CTRL) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_CAP_CTRL);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_CFG_DUMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_CFG_DUMP_OPCODE 51204
#define CXL_MEM_COMMAND_ID_OSA_CFG_DUMP_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_OSA_CFG_DUMP_PAYLOAD_OUT_SIZE 60

struct cxl_mbox_osa_cfg_dump_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
}  __attribute__((packed));

struct cxl_mbox_osa_cfg_dump_out {
	__le16 os_type_trig_cfg_lane_mask;
	u8 os_type_trig_cfg_lane_dir_mask;
	u8 os_type_trig_cfg_rate_mask;
	__le16 os_type_trig_cfg_os_type_mask;
	__le16 rsvd;
	__le16 os_patt_trig_cfg_lane_mask;
	u8 os_patt_trig_cfg_lane_dir_mask;
	u8 os_patt_trig_cfg_rate_mask;
	__le32 os_patt_trig_cfg_val[4];
	__le32 os_patt_trig_cfg_mask[4];
	u8 misc_trig_cfg_trig_en_mask;
	u8 rsvd45[3];
	__le16 cap_ctrl_lane_mask;
	u8 cap_ctrl_lane_dir_mask;
	u8 cap_ctrl_drop_single_os;
	u8 cap_ctrl_stop_mode;
	u8 cap_ctrl_snapshot_mode;
	__le16 cap_ctrl_post_trig_num;
	__le16 cap_ctrl_os_type_mask;
	__le16 rsvd58;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_osa_cfg_dump(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_cfg_dump_in *osa_cfg_dump_in;
	struct cxl_mbox_osa_cfg_dump_out *osa_cfg_dump_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_CFG_DUMP_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_CFG_DUMP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_cfg_dump_in = (void *) cmd->send_cmd->in.payload;

	osa_cfg_dump_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_CFG_DUMP) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_CFG_DUMP);
		return -EINVAL;
	}

	osa_cfg_dump_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================ osa configuration dump ============================\n");
	fprintf(stdout, "OS type triggering - lane mask: %x\n", le16_to_cpu(osa_cfg_dump_out->os_type_trig_cfg_lane_mask));
	fprintf(stdout, "OS type triggering - lane direction mask (see OSA_LANE_DIR_BITMSK_*): %x\n", osa_cfg_dump_out->os_type_trig_cfg_lane_dir_mask);
	fprintf(stdout, "OS type triggering - link rate mask (see OSA_LINK_RATE_BITMSK_*): %x\n", osa_cfg_dump_out->os_type_trig_cfg_rate_mask);
	fprintf(stdout, "OS type triggering - OS type mask (see OSA_OS_TYPE_TRIG_BITMSK_*): %x\n", le16_to_cpu(osa_cfg_dump_out->os_type_trig_cfg_os_type_mask));
	fprintf(stdout, "OS pattern triggering - lane mask: %x\n", le16_to_cpu(osa_cfg_dump_out->os_patt_trig_cfg_lane_mask));
	fprintf(stdout, "OS pattern triggering - lane direction mask (see OSA_LANE_DIR_BITMSK_*): %x\n", osa_cfg_dump_out->os_patt_trig_cfg_lane_dir_mask);
	fprintf(stdout, "OS pattern triggering - link rate mask (see OSA_LINK_RATE_BITMSK_*): %x\n", osa_cfg_dump_out->os_patt_trig_cfg_rate_mask);
	fprintf(stdout, "OS pattern triggering - pattern match value: ");
	/* Procedurally generated print statement. To print this array contiguously,
	   add "contiguous: True" to the YAML param and rerun cligen.py */
	for (int i = 0; i < 4; i++) {
		fprintf(stdout, "os_patt_trig_cfg_val[%d]: %x\n", i, le32_to_cpu(osa_cfg_dump_out->os_patt_trig_cfg_val[i]));
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "OS pattern triggering - pattern match mask: ");
	/* Procedurally generated print statement. To print this array contiguously,
	   add "contiguous: True" to the YAML param and rerun cligen.py */
	for (int i = 0; i < 4; i++) {
		fprintf(stdout, "os_patt_trig_cfg_mask[%d]: %x\n", i, le32_to_cpu(osa_cfg_dump_out->os_patt_trig_cfg_mask[i]));
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "miscellaneous triggering: %x\n", osa_cfg_dump_out->misc_trig_cfg_trig_en_mask);
	fprintf(stdout, "capture control - lane mask: %x\n", le16_to_cpu(osa_cfg_dump_out->cap_ctrl_lane_mask));
	fprintf(stdout, "capture control - lane direction mask (see OSA_LANE_DIR_BITMSK_*): %x\n", osa_cfg_dump_out->cap_ctrl_lane_dir_mask);
	fprintf(stdout, "capture control - drop single OS's (TS1/TS2/FTS/CTL_SKP): %x\n", osa_cfg_dump_out->cap_ctrl_drop_single_os);
	fprintf(stdout, "capture control - capture stop mode: %x\n", osa_cfg_dump_out->cap_ctrl_stop_mode);
	fprintf(stdout, "capture control - snapshot mode enable: %x\n", osa_cfg_dump_out->cap_ctrl_snapshot_mode);
	fprintf(stdout, "capture control: %x\n", le16_to_cpu(osa_cfg_dump_out->cap_ctrl_post_trig_num));
	fprintf(stdout, "capture control - OS type mask (see OSA_OS_TYPE_CAP_BITMSK_*): %x\n", le16_to_cpu(osa_cfg_dump_out->cap_ctrl_os_type_mask));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_ANA_OP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_ANA_OP_OPCODE 51205
#define CXL_MEM_COMMAND_ID_OSA_ANA_OP_PAYLOAD_IN_SIZE 4

struct cxl_mbox_osa_ana_op_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 op;
	u8 rsvd3;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_osa_ana_op(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 op)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_ana_op_in *osa_ana_op_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_ANA_OP_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_ANA_OP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_ana_op_in = (void *) cmd->send_cmd->in.payload;

	osa_ana_op_in->cxl_mem_id = cxl_mem_id;
	osa_ana_op_in->op = op;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_ANA_OP) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_ANA_OP);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY_OPCODE 51206
#define CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_osa_status_query_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
}  __attribute__((packed));

struct cxl_mbox_osa_status_query_out {
	u8 state;
	u8 lane_id;
	u8 lane_dir;
	u8 rsvd;
	__le16 trig_reason_mask;
	__le16 rsvd6;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_osa_status_query(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_status_query_in *osa_status_query_in;
	struct cxl_mbox_osa_status_query_out *osa_status_query_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_status_query_in = (void *) cmd->send_cmd->in.payload;

	osa_status_query_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_STATUS_QUERY);
		return -EINVAL;
	}

	osa_status_query_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=============================== osa status query ===============================\n");
	fprintf(stdout, "OSA state (see osa_state_enum): %x\n", osa_status_query_out->state);
	fprintf(stdout, "lane that caused the trigger: %x\n", osa_status_query_out->lane_id);
	fprintf(stdout, "direction of lane that caused the trigger (see osa_lane_dir_enum): %x\n", osa_status_query_out->lane_dir);
	fprintf(stdout, "trigger reason mask (see OSA_TRIG_REASON_BITMSK_*): %x\n", le16_to_cpu(osa_status_query_out->trig_reason_mask));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_ACCESS_REL CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_ACCESS_REL_OPCODE 51208
#define CXL_MEM_COMMAND_ID_OSA_ACCESS_REL_PAYLOAD_IN_SIZE 4

struct cxl_mbox_osa_access_rel_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_osa_access_rel(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_access_rel_in *osa_access_rel_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_ACCESS_REL_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_ACCESS_REL_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_access_rel_in = (void *) cmd->send_cmd->in.payload;

	osa_access_rel_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_ACCESS_REL) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_ACCESS_REL);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET_OPCODE 51712
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET_PAYLOAD_IN_SIZE 20

struct cxl_mbox_perfcnt_mta_ltif_set_in {
	__le32 counter;
	__le32 match_value;
	__le32 opcode;
	__le32 meta_field;
	__le32 meta_value;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_mta_ltif_set(struct cxl_memdev *memdev,
	u32 counter, u32 match_value, u32 opcode, u32 meta_field, u32 meta_value)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_ltif_set_in *perfcnt_mta_ltif_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_ltif_set_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_ltif_set_in->counter = cpu_to_le32(counter);
	perfcnt_mta_ltif_set_in->match_value = cpu_to_le32(match_value);
	perfcnt_mta_ltif_set_in->opcode = cpu_to_le32(opcode);
	perfcnt_mta_ltif_set_in->meta_field = cpu_to_le32(meta_field);
	perfcnt_mta_ltif_set_in->meta_value = cpu_to_le32(meta_value);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_LTIF_SET);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET_OPCODE 51713
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET_PAYLOAD_IN_SIZE 5
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_perfcnt_mta_get_in {
	u8 type;
	__le32 counter;
}  __attribute__((packed));

struct cxl_mbox_perfcnt_mta_get_out {
	__le64 counter;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_perfcnt_mta_get(struct cxl_memdev *memdev,
	u8 type, u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_get_in *perfcnt_mta_get_in;
	struct cxl_mbox_perfcnt_mta_get_out *perfcnt_mta_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_get_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_get_in->type = type;
	perfcnt_mta_get_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_GET);
		return -EINVAL;
	}

	perfcnt_mta_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================= mta get performance counter ==========================\n");
	fprintf(stdout, "Counter: %lx\n", le64_to_cpu(perfcnt_mta_get_out->counter));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET_OPCODE 51714
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET_PAYLOAD_IN_SIZE 5
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_perfcnt_mta_latch_val_get_in {
	u8 type;
	__le32 counter;
}  __attribute__((packed));

struct cxl_mbox_perfcnt_mta_latch_val_get_out {
	__le64 latch_val;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_perfcnt_mta_latch_val_get(struct cxl_memdev *memdev,
	u8 type, u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_latch_val_get_in *perfcnt_mta_latch_val_get_in;
	struct cxl_mbox_perfcnt_mta_latch_val_get_out *perfcnt_mta_latch_val_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_latch_val_get_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_latch_val_get_in->type = type;
	perfcnt_mta_latch_val_get_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_LATCH_VAL_GET);
		return -EINVAL;
	}

	perfcnt_mta_latch_val_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================= mta get latch value ==============================\n");
	fprintf(stdout, "Latch value: %lx\n", le64_to_cpu(perfcnt_mta_latch_val_get_out->latch_val));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR_OPCODE 51715
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR_PAYLOAD_IN_SIZE 5

struct cxl_mbox_perfcnt_mta_counter_clear_in {
	u8 type;
	__le32 counter;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_mta_counter_clear(struct cxl_memdev *memdev,
	u8 type, u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_counter_clear_in *perfcnt_mta_counter_clear_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_counter_clear_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_counter_clear_in->type = type;
	perfcnt_mta_counter_clear_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_COUNTER_CLEAR);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH_OPCODE 51716
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH_PAYLOAD_IN_SIZE 5

struct cxl_mbox_perfcnt_mta_cnt_val_latch_in {
	u8 type;
	__le32 counter;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_mta_cnt_val_latch(struct cxl_memdev *memdev,
	u8 type, u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_cnt_val_latch_in *perfcnt_mta_cnt_val_latch_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_cnt_val_latch_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_cnt_val_latch_in->type = type;
	perfcnt_mta_cnt_val_latch_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_CNT_VAL_LATCH);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET_OPCODE 51717
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET_PAYLOAD_IN_SIZE 20

struct cxl_mbox_perfcnt_mta_hif_set_in {
	__le32 counter;
	__le32 match_value;
	__le32 addr;
	__le32 req_ty;
	__le32 sc_ty;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_mta_hif_set(struct cxl_memdev *memdev,
	u32 counter, u32 match_value, u32 addr, u32 req_ty, u32 sc_ty)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_hif_set_in *perfcnt_mta_hif_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_hif_set_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_hif_set_in->counter = cpu_to_le32(counter);
	perfcnt_mta_hif_set_in->match_value = cpu_to_le32(match_value);
	perfcnt_mta_hif_set_in->addr = cpu_to_le32(addr);
	perfcnt_mta_hif_set_in->req_ty = cpu_to_le32(req_ty);
	perfcnt_mta_hif_set_in->sc_ty = cpu_to_le32(sc_ty);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_SET);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET_OPCODE 51718
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_perfcnt_mta_hif_cfg_get_in {
	__le32 counter;
}  __attribute__((packed));

struct cxl_mbox_perfcnt_mta_hif_cfg_get_out {
	__le64 counter;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_perfcnt_mta_hif_cfg_get(struct cxl_memdev *memdev,
	u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_hif_cfg_get_in *perfcnt_mta_hif_cfg_get_in;
	struct cxl_mbox_perfcnt_mta_hif_cfg_get_out *perfcnt_mta_hif_cfg_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_hif_cfg_get_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_hif_cfg_get_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CFG_GET);
		return -EINVAL;
	}

	perfcnt_mta_hif_cfg_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================== mta get hif configuration ===========================\n");
	fprintf(stdout, "Counter: %lx\n", le64_to_cpu(perfcnt_mta_hif_cfg_get_out->counter));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET_OPCODE 51719
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_perfcnt_mta_hif_latch_val_get_in {
	__le32 counter;
}  __attribute__((packed));

struct cxl_mbox_perfcnt_mta_hif_latch_val_get_out {
	__le64 latch_val;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_perfcnt_mta_hif_latch_val_get(struct cxl_memdev *memdev,
	u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_hif_latch_val_get_in *perfcnt_mta_hif_latch_val_get_in;
	struct cxl_mbox_perfcnt_mta_hif_latch_val_get_out *perfcnt_mta_hif_latch_val_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_hif_latch_val_get_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_hif_latch_val_get_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_LATCH_VAL_GET);
		return -EINVAL;
	}

	perfcnt_mta_hif_latch_val_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== mta get hif latch value ============================\n");
	fprintf(stdout, "Latch value: %lx\n", le64_to_cpu(perfcnt_mta_hif_latch_val_get_out->latch_val));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR_OPCODE 51720
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR_PAYLOAD_IN_SIZE 4

struct cxl_mbox_perfcnt_mta_hif_counter_clear_in {
	__le32 counter;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_mta_hif_counter_clear(struct cxl_memdev *memdev,
	u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_hif_counter_clear_in *perfcnt_mta_hif_counter_clear_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_hif_counter_clear_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_hif_counter_clear_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_COUNTER_CLEAR);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH_OPCODE 51721
#define CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH_PAYLOAD_IN_SIZE 4

struct cxl_mbox_perfcnt_mta_hif_cnt_val_latch_in {
	__le32 counter;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_mta_hif_cnt_val_latch(struct cxl_memdev *memdev,
	u32 counter)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_mta_hif_cnt_val_latch_in *perfcnt_mta_hif_cnt_val_latch_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_mta_hif_cnt_val_latch_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_mta_hif_cnt_val_latch_in->counter = cpu_to_le32(counter);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_MTA_HIF_CNT_VAL_LATCH);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT_OPCODE 51728
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT_PAYLOAD_IN_SIZE 13

struct cxl_mbox_perfcnt_ddr_generic_select_in {
	u8 ddr_id;
	u8 cid;
	u8 rank;
	u8 bank;
	u8 bankgroup;
	__le64 event;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_perfcnt_ddr_generic_select(struct cxl_memdev *memdev,
	u8 ddr_id, u8 cid, u8 rank, u8 bank, u8 bankgroup, u64 event)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_ddr_generic_select_in *perfcnt_ddr_generic_select_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_ddr_generic_select_in = (void *) cmd->send_cmd->in.payload;

	perfcnt_ddr_generic_select_in->ddr_id = ddr_id;
	perfcnt_ddr_generic_select_in->cid = cid;
	perfcnt_ddr_generic_select_in->rank = rank;
	perfcnt_ddr_generic_select_in->bank = bank;
	perfcnt_ddr_generic_select_in->bankgroup = bankgroup;
	perfcnt_ddr_generic_select_in->event = cpu_to_le64(event);

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_SELECT);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON_OPCODE 51970
#define CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON_PAYLOAD_IN_SIZE 6

struct cxl_mbox_err_inj_drs_poison_in {
	u8 ch_id;
	u8 duration;
	u8 inj_mode;
	u8 rsvd;
	__le16 tag;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_err_inj_drs_poison(struct cxl_memdev *memdev,
	u8 ch_id, u8 duration, u8 inj_mode, u16 tag)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_drs_poison_in *err_inj_drs_poison_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_drs_poison_in = (void *) cmd->send_cmd->in.payload;

	err_inj_drs_poison_in->ch_id = ch_id;
	err_inj_drs_poison_in->duration = duration;
	err_inj_drs_poison_in->inj_mode = inj_mode;
	err_inj_drs_poison_in->tag = cpu_to_le16(tag);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_ERR_INJ_DRS_POISON);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC_OPCODE 51971
#define CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC_PAYLOAD_IN_SIZE 6

struct cxl_mbox_err_inj_drs_ecc_in {
	u8 ch_id;
	u8 duration;
	u8 inj_mode;
	u8 rsvd;
	__le16 tag;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_err_inj_drs_ecc(struct cxl_memdev *memdev,
	u8 ch_id, u8 duration, u8 inj_mode, u16 tag)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_drs_ecc_in *err_inj_drs_ecc_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_drs_ecc_in = (void *) cmd->send_cmd->in.payload;

	err_inj_drs_ecc_in->ch_id = ch_id;
	err_inj_drs_ecc_in->duration = duration;
	err_inj_drs_ecc_in->inj_mode = inj_mode;
	err_inj_drs_ecc_in->tag = cpu_to_le16(tag);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_ERR_INJ_DRS_ECC);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC_OPCODE 51972
#define CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC_PAYLOAD_IN_SIZE 1

struct cxl_mbox_err_inj_rxflit_crc_in {
	u8 cxl_mem_id;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_err_inj_rxflit_crc(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_rxflit_crc_in *err_inj_rxflit_crc_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_rxflit_crc_in = (void *) cmd->send_cmd->in.payload;

	err_inj_rxflit_crc_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_ERR_INJ_RXFLIT_CRC);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC_OPCODE 51973
#define CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC_PAYLOAD_IN_SIZE 1

struct cxl_mbox_err_inj_txflit_crc_in {
	u8 cxl_mem_id;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_err_inj_txflit_crc(struct cxl_memdev *memdev,
	u8 cxl_mem_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_txflit_crc_in *err_inj_txflit_crc_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_txflit_crc_in = (void *) cmd->send_cmd->in.payload;

	err_inj_txflit_crc_in->cxl_mem_id = cxl_mem_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_ERR_INJ_TXFLIT_CRC);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL_OPCODE 51974
#define CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL_PAYLOAD_IN_SIZE 1

struct cxl_mbox_err_inj_viral_in {
	u8 ld_id;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_err_inj_viral(struct cxl_memdev *memdev,
	u8 ld_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_viral_in *err_inj_viral_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_viral_in = (void *) cmd->send_cmd->in.payload;

	err_inj_viral_in->ld_id = ld_id;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_ERR_INJ_VIRAL);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN_OPCODE 52224
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN_PAYLOAD_IN_SIZE 8

struct cxl_mbox_eh_eye_cap_run_in {
	u8 rsvd;
	u8 depth;
	__le16 rsvd2;
	__le32 lane_mask;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_eh_eye_cap_run(struct cxl_memdev *memdev,
	u8 depth, u32 lane_mask)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_eye_cap_run_in *eh_eye_cap_run_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_eye_cap_run_in = (void *) cmd->send_cmd->in.payload;

	eh_eye_cap_run_in->depth = depth;
	eh_eye_cap_run_in->lane_mask = cpu_to_le32(lane_mask);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_EH_EYE_CAP_RUN);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ_OPCODE 52226
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ_PAYLOAD_OUT_SIZE 248

struct cxl_mbox_eh_eye_cap_read_in {
	u8 rsvd;
	u8 lane_id;
	u8 bin_num;
	u8 rsvd3;
}  __attribute__((packed));

struct cxl_mbox_eh_eye_cap_read_out {
	u8 num_phase;
	u8 rsvd[7];
	__le32 ber_data[60];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_eh_eye_cap_read(struct cxl_memdev *memdev,
	u8 lane_id, u8 bin_num)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_eye_cap_read_in *eh_eye_cap_read_in;
	struct cxl_mbox_eh_eye_cap_read_out *eh_eye_cap_read_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_eye_cap_read_in = (void *) cmd->send_cmd->in.payload;

	eh_eye_cap_read_in->lane_id = lane_id;
	eh_eye_cap_read_in->bin_num = bin_num;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_EH_EYE_CAP_READ);
		return -EINVAL;
	}

	eh_eye_cap_read_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================= eh eye capture read ==============================\n");
	fprintf(stdout, "Total number of phases in ber_data: %x\n", eh_eye_cap_read_out->num_phase);
	fprintf(stdout, "Per-phase bit error rates (multiplied by EYE_CAP_ERROR_CNT_MULT): ");
	/* Procedurally generated print statement. To print this array contiguously,
	   add "contiguous: True" to the YAML param and rerun cligen.py */
	for (int i = 0; i < 60; i++) {
		fprintf(stdout, "ber_data[%d]: %x\n", i, le32_to_cpu(eh_eye_cap_read_out->ber_data[i]));
	}
	fprintf(stdout, "\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_EH_ADAPT_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_ADAPT_GET_OPCODE 52227
#define CXL_MEM_COMMAND_ID_EH_ADAPT_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_EH_ADAPT_GET_PAYLOAD_OUT_SIZE 28

struct cxl_mbox_eh_adapt_get_in {
	__le32 lane_id;
}  __attribute__((packed));

struct cxl_mbox_eh_adapt_get_out {
	u8 pga_gain;
	u8 pga_off2;
	u8 pga_off1;
	u8 cdfe_a2;
	u8 cdfe_a3;
	u8 cdfe_a4;
	u8 cdfe_a5;
	u8 cdfe_a6;
	u8 cdfe_a7;
	u8 cdfe_a8;
	u8 cdfe_a9;
	u8 cdfe_a10;
	u8 zobel_a_gain;
	u8 zobel_b_gain;
	__le16 zobel_dc_offset;
	__le16 udfe_thr_0;
	__le16 udfe_thr_1;
	__le16 dc_offset;
	__le16 median_amp;
	u8 ph_ofs_t;
	u8 rsvd[3];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_eh_adapt_get(struct cxl_memdev *memdev,
	u32 lane_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_adapt_get_in *eh_adapt_get_in;
	struct cxl_mbox_eh_adapt_get_out *eh_adapt_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_ADAPT_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_ADAPT_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_adapt_get_in = (void *) cmd->send_cmd->in.payload;

	eh_adapt_get_in->lane_id = cpu_to_le32(lane_id);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_ADAPT_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_EH_ADAPT_GET);
		return -EINVAL;
	}

	eh_adapt_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================ eh get adaptation data ============================\n");
	fprintf(stdout, "contain the current value of the object PGA_GAIN as captured through a write to register bit ADAPT_DSP_RESULTS_CAPTURE_REQ: %x\n", eh_adapt_get_out->pga_gain);
	fprintf(stdout, "PGA Stage2 DC offset correction: %x\n", eh_adapt_get_out->pga_off2);
	fprintf(stdout, "PGA Stage1 DC offset correction: %x\n", eh_adapt_get_out->pga_off1);
	fprintf(stdout, "I_TAP2<7:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a2);
	fprintf(stdout, "I_TAP3<6:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a3);
	fprintf(stdout, "I_TAP4<6:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a4);
	fprintf(stdout, "I_TAP5<6:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a5);
	fprintf(stdout, "I_TAP6<6:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a6);
	fprintf(stdout, "I_TAP7<6:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a7);
	fprintf(stdout, "I_TAP8<6:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a8);
	fprintf(stdout, "I_TAP9<5:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a9);
	fprintf(stdout, "I_TAP10<5:0> 2's compliment: %x\n", eh_adapt_get_out->cdfe_a10);
	fprintf(stdout, "Zobel a_gain: %x\n", eh_adapt_get_out->zobel_a_gain);
	fprintf(stdout, "zobel_b_gain: %x\n", eh_adapt_get_out->zobel_b_gain);
	fprintf(stdout, "Zobel DC offset correction: %x\n", le16_to_cpu(eh_adapt_get_out->zobel_dc_offset));
	fprintf(stdout, "contain the current value of the object UDFE_THR_0 as captured through a write to register bit ADAPT_DSP_RESULTS_CAPTURE_REQ.: %x\n", le16_to_cpu(eh_adapt_get_out->udfe_thr_0));
	fprintf(stdout, "contain the current value of the object UDFE_THR_1 as captured through a write to register bit ADAPT_DSP_RESULTS_CAPTURE_REQ: %x\n", le16_to_cpu(eh_adapt_get_out->udfe_thr_1));
	fprintf(stdout, "contain the current value of the object DC_OFFSET as captured through a write to register bit ADAPT_DSP_RESULTS_CAPTURE_REQ: %x\n", le16_to_cpu(eh_adapt_get_out->dc_offset));
	fprintf(stdout, "contain the current value of the object PGA_GAIN as captured through a write to register bit ADAPT_DSP_RESULTS_CAPTURE_REQ: %x\n", le16_to_cpu(eh_adapt_get_out->median_amp));
	fprintf(stdout, "contain the current value of the object PH_OFS_T as captured through a write to register bit ADAPT_DSP_RESULTS_CAPTURE_REQ: %x\n", eh_adapt_get_out->ph_ofs_t);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF_OPCODE 52228
#define CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF_PAYLOAD_IN_SIZE 16

struct cxl_mbox_eh_adapt_oneoff_in {
	__le32 lane_id;
	__le32 preload;
	__le32 loops;
	__le32 objects;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_eh_adapt_oneoff(struct cxl_memdev *memdev,
	u32 lane_id, u32 preload, u32 loops, u32 objects)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_adapt_oneoff_in *eh_adapt_oneoff_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_adapt_oneoff_in = (void *) cmd->send_cmd->in.payload;

	eh_adapt_oneoff_in->lane_id = cpu_to_le32(lane_id);
	eh_adapt_oneoff_in->preload = cpu_to_le32(preload);
	eh_adapt_oneoff_in->loops = cpu_to_le32(loops);
	eh_adapt_oneoff_in->objects = cpu_to_le32(objects);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_EH_ADAPT_ONEOFF);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE_OPCODE 52229
#define CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE_PAYLOAD_IN_SIZE 40

struct cxl_mbox_eh_adapt_force_in {
	__le32 lane_id;
	__le32 rate;
	__le32 vdd_bias;
	__le32 ssc;
	u8 pga_gain;
	u8 pga_a0;
	u8 pga_off;
	u8 cdfe_a2;
	u8 cdfe_a3;
	u8 cdfe_a4;
	u8 cdfe_a5;
	u8 cdfe_a6;
	u8 cdfe_a7;
	u8 cdfe_a8;
	u8 cdfe_a9;
	u8 cdfe_a10;
	__le16 dc_offset;
	__le16 zobel_dc_offset;
	__le16 udfe_thr_0;
	__le16 udfe_thr_1;
	__le16 median_amp;
	u8 zobel_a_gain;
	u8 ph_ofs_t;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_eh_adapt_force(struct cxl_memdev *memdev,
	u32 lane_id, u32 rate, u32 vdd_bias, u32 ssc, u8 pga_gain, u8 pga_a0,
	u8 pga_off, u8 cdfe_a2, u8 cdfe_a3, u8 cdfe_a4, u8 cdfe_a5, u8 cdfe_a6,
	u8 cdfe_a7, u8 cdfe_a8, u8 cdfe_a9, u8 cdfe_a10, u16 dc_offset,
	u16 zobel_dc_offset, u16 udfe_thr_0, u16 udfe_thr_1, u16 median_amp,
	u8 zobel_a_gain, u8 ph_ofs_t)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_adapt_force_in *eh_adapt_force_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_adapt_force_in = (void *) cmd->send_cmd->in.payload;

	eh_adapt_force_in->lane_id = cpu_to_le32(lane_id);
	eh_adapt_force_in->rate = cpu_to_le32(rate);
	eh_adapt_force_in->vdd_bias = cpu_to_le32(vdd_bias);
	eh_adapt_force_in->ssc = cpu_to_le32(ssc);
	eh_adapt_force_in->pga_gain = pga_gain;
	eh_adapt_force_in->pga_a0 = pga_a0;
	eh_adapt_force_in->pga_off = pga_off;
	eh_adapt_force_in->cdfe_a2 = cdfe_a2;
	eh_adapt_force_in->cdfe_a3 = cdfe_a3;
	eh_adapt_force_in->cdfe_a4 = cdfe_a4;
	eh_adapt_force_in->cdfe_a5 = cdfe_a5;
	eh_adapt_force_in->cdfe_a6 = cdfe_a6;
	eh_adapt_force_in->cdfe_a7 = cdfe_a7;
	eh_adapt_force_in->cdfe_a8 = cdfe_a8;
	eh_adapt_force_in->cdfe_a9 = cdfe_a9;
	eh_adapt_force_in->cdfe_a10 = cdfe_a10;
	eh_adapt_force_in->dc_offset = cpu_to_le16(dc_offset);
	eh_adapt_force_in->zobel_dc_offset = cpu_to_le16(zobel_dc_offset);
	eh_adapt_force_in->udfe_thr_0 = cpu_to_le16(udfe_thr_0);
	eh_adapt_force_in->udfe_thr_1 = cpu_to_le16(udfe_thr_1);
	eh_adapt_force_in->median_amp = cpu_to_le16(median_amp);
	eh_adapt_force_in->zobel_a_gain = zobel_a_gain;
	eh_adapt_force_in->ph_ofs_t = ph_ofs_t;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_EH_ADAPT_FORCE);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HBO_STATUS CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HBO_STATUS_OPCODE 52480
#define CXL_MEM_COMMAND_ID_HBO_STATUS_PAYLOAD_OUT_SIZE 8


struct cxl_mbox_hbo_status_out {
	__le64 bo_status;
}  __attribute__((packed));

struct hbo_status_fields {
	u16 opcode;
	u8 percent_complete;
	u8 is_running;
	u16 return_code;
	u16 extended_status;
};

CXL_EXPORT int cxl_memdev_hbo_status(struct cxl_memdev *memdev, u8 print_output)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_hbo_status_out *hbo_status_out;
	struct hbo_status_fields status_fields;
	u8 opcode_shift = 0;
	u8 percent_shift = 16;
	u8 running_shift = 23;
	u8 retcode_shift = 32;
	u8 extended_shift = 48;
	u64 opcode_mask = (1 << percent_shift) - (1 << opcode_shift); // 0-15
	u64 percent_mask = (1 << running_shift) - (1 << percent_shift); // 16-22
	u64 running_mask = (1 << running_shift); // 23
	u64 retcode_mask = (1 << extended_shift) - (1 << retcode_shift); // 32-47
	u64 extended_mask = 0xffffffffffffffff - (1 << extended_shift) + 1; // 48-63
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HBO_STATUS_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HBO_STATUS) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HBO_STATUS);
		return -EINVAL;
	}

	hbo_status_out = (void *)cmd->send_cmd->out.payload;
	status_fields.opcode = (hbo_status_out->bo_status & opcode_mask) >> opcode_shift;
	status_fields.percent_complete = (hbo_status_out->bo_status & percent_mask) >> percent_shift;
	status_fields.is_running = (hbo_status_out->bo_status & running_mask) >> running_shift;
	status_fields.return_code = (hbo_status_out->bo_status & retcode_mask) >> retcode_shift;
	status_fields.extended_status = (hbo_status_out->bo_status & extended_mask) >> extended_shift;
	if (print_output)
	{
		fprintf(stdout, "=============================== hidden bo status ===============================\n");
		fprintf(stdout, "BO status: %08lx\n", le64_to_cpu(hbo_status_out->bo_status));
		fprintf(stdout, " - Opcode: %x\n", status_fields.opcode);
		fprintf(stdout, " - Percent complete: %d\n", status_fields.percent_complete);
		fprintf(stdout, " - Is running: %d\n", status_fields.is_running);
		fprintf(stdout, " - Return code: %d\n", status_fields.return_code);
		fprintf(stdout, " - Extended status: %x\n", status_fields.extended_status);
	}

    if (status_fields.is_running) {
        rc = 1;
    }
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HBO_TRANSFER_FW CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HBO_TRANSFER_FW_OPCODE 52481



CXL_EXPORT int cxl_memdev_hbo_transfer_fw(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HBO_TRANSFER_FW_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HBO_TRANSFER_FW) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HBO_TRANSFER_FW);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HBO_ACTIVATE_FW CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HBO_ACTIVATE_FW_OPCODE 52482



CXL_EXPORT int cxl_memdev_hbo_activate_fw(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HBO_ACTIVATE_FW_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HBO_ACTIVATE_FW) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HBO_ACTIVATE_FW);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR_OPCODE 52736
#define CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR_PAYLOAD_IN_SIZE 4

struct cxl_mbox_health_counters_clear_in {
	__le32 bitmask;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_health_counters_clear(struct cxl_memdev *memdev,
	u32 bitmask)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_health_counters_clear_in *health_counters_clear_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	health_counters_clear_in = (void *) cmd->send_cmd->in.payload;

	health_counters_clear_in->bitmask = cpu_to_le32(bitmask);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_CLEAR);
		return -EINVAL;
	}


out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_GET_OPCODE 52737
#define CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_GET_PAYLOAD_OUT_SIZE 40

struct cxl_mbox_health_counters_get_out {
	__le32 critical_over_temperature_exceeded;
	__le32 power_on_events;
	__le32 power_on_hours;
	__le32 cxl_mem_link_crc_errors;
	__le32 cxl_io_link_lcrc_errors;
	__le32 cxl_io_link_ecrc_errors;
	__le32 num_ddr_single_ecc_errors;
	__le32 num_ddr_double_ecc_errors;
	__le32 link_recovery_events;
	__le32 time_in_throttled;
	__le32 over_temperature_warning_level_exceeded;
	__le32 critical_under_temperature_exceeded;
	__le32 under_temperature_warning_level_exceeded;
	__le32 rx_retry_request;
	__le32 rcmd_qs0_hi_threshold_detect;
	__le32 rcmd_qs1_hi_threshold_detect;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_health_counters_get(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_health_counters_get_out *health_counters_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HEALTH_COUNTERS_GET);
		return -EINVAL;
	}

	health_counters_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "============================= get health counters ==============================\n");
	fprintf(stdout, "0: CRITICAL_OVER_TEMPERATURE_EXCEEDED = %d\n", le32_to_cpu(health_counters_get_out->critical_over_temperature_exceeded));
	fprintf(stdout, "1: OVER_TEMPERATURE_WARNING_LEVEL_EXCEEDED = %d\n", le32_to_cpu(health_counters_get_out->over_temperature_warning_level_exceeded));
	fprintf(stdout, "2: CRITICAL_UNDER_TEMPERATURE_EXCEEDED = %d\n", le32_to_cpu(health_counters_get_out->critical_under_temperature_exceeded));
	fprintf(stdout, "3: UNDER_TEMPERATURE_WARNING_LEVEL_EXCEEDED = %d\n", le32_to_cpu(health_counters_get_out->under_temperature_warning_level_exceeded));
	fprintf(stdout, "4: POWER_ON_EVENTS = %d\n", le32_to_cpu(health_counters_get_out->power_on_events));
	fprintf(stdout, "5: POWER_ON_HOURS = %d\n", le32_to_cpu(health_counters_get_out->power_on_hours));
	fprintf(stdout, "6: CXL_MEM_LINK_CRC_ERRORS = %d\n", le32_to_cpu(health_counters_get_out->cxl_mem_link_crc_errors));
	fprintf(stdout, "7: CXL_IO_LINK_LCRC_ERRORS = %d\n", le32_to_cpu(health_counters_get_out->cxl_io_link_lcrc_errors));
	fprintf(stdout, "8: CXL_IO_LINK_ECRC_ERRORS = %d\n", le32_to_cpu(health_counters_get_out->cxl_io_link_ecrc_errors));
	fprintf(stdout, "9: NUM_DDR_SINGLE_ECC_ERRORS = %d\n", le32_to_cpu(health_counters_get_out->num_ddr_single_ecc_errors));
	fprintf(stdout, "10: NUM_DDR_DOUBLE_ECC_ERRORS = %d\n", le32_to_cpu(health_counters_get_out->num_ddr_double_ecc_errors));
	fprintf(stdout, "11: LINK_RECOVERY_EVENTS = %d\n", le32_to_cpu(health_counters_get_out->link_recovery_events));
	fprintf(stdout, "12: TIME_IN_THROTTLED = %d\n", le32_to_cpu(health_counters_get_out->time_in_throttled));
	fprintf(stdout, "13: RX_RETRY_REQUEST = %d\n", le32_to_cpu(health_counters_get_out->rx_retry_request));
	fprintf(stdout, "14: RCMD_QS0_HI_THRESHOLD_DETECT = %d\n", le32_to_cpu(health_counters_get_out->rcmd_qs0_hi_threshold_detect));
	fprintf(stdout, "15: RCMD_QS1_HI_THRESHOLD_DETECT = %d\n", le32_to_cpu(health_counters_get_out->rcmd_qs1_hi_threshold_detect));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_HCT_GET_PLAT_PARAMS CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_GET_PLAT_PARAMS_OPCODE 0xC600
#define CXL_MEM_COMMAND_ID_HCT_GET_PLAT_PARAMS_OUT_SIZE 8 // varies


struct cxl_mbox_hct_get_plat_param_out {
	u8 num_inst;
	u8* type;
}  __attribute__((packed));

const char *TRACE_BUF_INST_TYPE[2] = {
	"FLIT",
	"HIF",
};

CXL_EXPORT int cxl_memdev_hct_get_plat_param(struct cxl_memdev *memdev)
{
	u8 *out_ptr;
	struct cxl_cmd *cmd;
	struct cxl_mbox_hct_get_plat_param_out *hct_get_plat_param_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_GET_PLAT_PARAMS_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
			cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
			cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
			cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_GET_PLAT_PARAMS) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
			cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_GET_PLAT_PARAMS);
		return -EINVAL;
	}

	hct_get_plat_param_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=============================== Get HIF/CXL Trace Buffer Platform Parameters ===============================\n");
	fprintf(stdout, "Number of trace buffer instances: %u\n", hct_get_plat_param_out->num_inst);
	out_ptr = (u8*) cmd->send_cmd->out.payload;
	for (int i = 1; i < cmd->send_cmd->out.size; i++) {
		printf("Instance: %d type %02x %s\n", i, out_ptr[i], TRACE_BUF_INST_TYPE[out_ptr[i]]);
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON_OPCODE 0XCB00
#define CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON_PAYLOAD_IN_SIZE 9
#define HIF_POISON_ADDRESS_SIZE 5


struct cxl_mbox_err_inj_hif_poison_in {
	u8 ch_id;
	u8 duration;
	u8 inj_mode;
	u8 rsvd;
	char *address[HIF_POISON_ADDRESS_SIZE];
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_err_inj_hif_poison(struct cxl_memdev *memdev,
	u8 ch_id, u8 duration, u8 inj_mode, u64 address)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_hif_poison_in *err_inj_hif_poison_in;
	int rc = 0;

	__le64 leaddress;
	leaddress = cpu_to_le64(address);

	cmd = cxl_cmd_new_raw(memdev,
	CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_hif_poison_in = (void *) cmd->send_cmd->in.payload;
	err_inj_hif_poison_in->ch_id = ch_id;
	err_inj_hif_poison_in->duration = duration;
	err_inj_hif_poison_in->inj_mode = inj_mode;
	memcpy(err_inj_hif_poison_in->address, &leaddress, HIF_POISON_ADDRESS_SIZE);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_ERR_INJ_HIF_POISON);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC_OPCODE 0XCB01
#define CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC_PAYLOAD_IN_SIZE 9
#define HIF_ECC_ADDRESS_SIZE 5


struct cxl_mbox_err_inj_hif_ecc_in {
	u8 ch_id;
	u8 duration;
	u8 inj_mode;
	u8 rsvd;
	char *address[HIF_ECC_ADDRESS_SIZE];
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_err_inj_hif_ecc(struct cxl_memdev *memdev,
	u8 ch_id, u8 duration, u8 inj_mode, u64 address)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_err_inj_hif_ecc_in *err_inj_hif_ecc_in;
	int rc = 0;

	__le64 leaddress;
	leaddress = cpu_to_le64(address);

	cmd = cxl_cmd_new_raw(memdev,
	CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	err_inj_hif_ecc_in = (void *) cmd->send_cmd->in.payload;
	err_inj_hif_ecc_in->ch_id = ch_id;
	err_inj_hif_ecc_in->duration = duration;
	err_inj_hif_ecc_in->inj_mode = inj_mode;
	memcpy(err_inj_hif_ecc_in->address, &leaddress, HIF_ECC_ADDRESS_SIZE);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_ERR_INJ_HIF_ECC);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE_OPCODE 0XCA11
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE_PAYLOAD_IN_SIZE 8
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE_PAYLOAD_OUT_SIZE 32

struct cxl_mbox_perfcnt_ddr_generic_capture_in {
	u8 ddr_id;
	u8 rsvd[3];
	__le32 poll_period_ms;
} __attribute__((packed));

struct cxl_mbox_perfcnt_ddr_generic_capture_out {
	__le32 result[32];
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_perfcnt_ddr_generic_capture(struct cxl_memdev *memdev,
	u8 ddr_id, u32 poll_period_ms)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_ddr_generic_capture_in *perfcnt_ddr_generic_capture_in;
	struct cxl_mbox_perfcnt_ddr_generic_capture_out *perfcnt_ddr_generic_capture_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev,
	CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_ddr_generic_capture_in = (void *) cmd->send_cmd->in.payload;
	perfcnt_ddr_generic_capture_in->ddr_id = ddr_id;
	perfcnt_ddr_generic_capture_in->poll_period_ms = cpu_to_le32(poll_period_ms);

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_PERFCNT_DDR_GENERIC_CAPTURE);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

	perfcnt_ddr_generic_capture_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== PERFCNT DDR Generic Capture ============================\n");
	fprintf(stdout, "Generic Counter Readings:\n");
	for(int i=0; i<8; i++) {
		fprintf(stdout, "%x\n", le32_to_cpu(perfcnt_ddr_generic_capture_out->result[i]));
	}
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE_OPCODE 0XCA12
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE_PAYLOAD_IN_SIZE 8
#define CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE_PAYLOAD_OUT_SIZE 24

struct cxl_mbox_perfcnt_ddr_dfi_capture_in {
	u8 ddr_id;
	u8 rsvd[3];
	__le32 poll_period_ms;
} __attribute__((packed));

struct cxl_mbox_perfcnt_ddr_dfi_capture_out {
	__le32 dfi_counter17;
	__le32 dfi_counter20;
	__le32 dfi_counter21;
	__le32 dfi_ch1_counter17;
	__le32 dfi_ch1_counter20;
	__le32 dfi_ch1_counter21;
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_perfcnt_ddr_dfi_capture(struct cxl_memdev *memdev,
	u8 ddr_id, u32 poll_period_ms)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_perfcnt_ddr_dfi_capture_in *perfcnt_ddr_dfi_capture_in;
	struct cxl_mbox_perfcnt_ddr_dfi_capture_out *perfcnt_ddr_dfi_capture_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev,
	CXL_MEM_COMMAND_ID_GET_EVENT_INTERRUPT_POLICY_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];
	cinfo->size_in = CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	perfcnt_ddr_dfi_capture_in = (void *) cmd->send_cmd->in.payload;
	perfcnt_ddr_dfi_capture_in->ddr_id = ddr_id;
	perfcnt_ddr_dfi_capture_in->poll_period_ms = cpu_to_le32(poll_period_ms);

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_PERFCNT_DDR_DFI_CAPTURE);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
	perfcnt_ddr_dfi_capture_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== PERFCNT DDR DFI Capture ============================\n");
	fprintf(stdout, "DFI Counter Readings:\n");
	fprintf(stdout, "DFI Counter 17: %x\n", le32_to_cpu(perfcnt_ddr_dfi_capture_out->dfi_counter17));
	fprintf(stdout, "DFI Counter 20: %x\n", le32_to_cpu(perfcnt_ddr_dfi_capture_out->dfi_counter20));
	fprintf(stdout, "DFI Counter 21: %x\n", le32_to_cpu(perfcnt_ddr_dfi_capture_out->dfi_counter21));
	fprintf(stdout, "DFI CH1 Counter 17: %x\n", le32_to_cpu(perfcnt_ddr_dfi_capture_out->dfi_ch1_counter17));
	fprintf(stdout, "DFI CH1 Counter 20: %x\n", le32_to_cpu(perfcnt_ddr_dfi_capture_out->dfi_ch1_counter20));
	fprintf(stdout, "DFI CH1 Counter 21: %x\n", le32_to_cpu(perfcnt_ddr_dfi_capture_out->dfi_ch1_counter21));
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE_OPCODE 0XCC0A
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE_PAYLOAD_IN_SIZE 2

struct cxl_mbox_eh_eye_cap_timeout_enable_in {
	u8 rsvd;
	u8 enable;
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_eh_eye_cap_timeout_enable(struct cxl_memdev *memdev, u8 enable)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_eye_cap_timeout_enable_in *eh_eye_cap_timeout_enable_in;
	int rc=0;

	cmd = cxl_cmd_new_raw(memdev,
	CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

		query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_eye_cap_timeout_enable_in = (void *) cmd->send_cmd->in.payload;
	eh_eye_cap_timeout_enable_in->enable = enable;

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_EH_EYE_CAP_TIMEOUT_ENABLE);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS_OPCODE 0XCC01
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS_PAYLOAD_OUT_SIZE 4

struct cxl_mbox_eh_eye_cap_status_in {
	u8 rsvd;
	u8 rsvd2[3];
} __attribute__((packed));

struct cxl_mbox_eh_eye_cap_status_out {
	u8 stat;
	u8 rsvd[3];
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_eh_eye_cap_status(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_eye_cap_status_out *eh_eye_cap_status_out;
	int rc=0;

	cmd = cxl_cmd_new_raw(memdev,
	CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

		query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_EH_EYE_CAP_STATUS);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
	eh_eye_cap_status_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== EH Eye Cap Status ============================\n");
	fprintf(stdout, "Status: %x\n", eh_eye_cap_status_out->stat);
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG_OPCODE 0XCC06
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG_PAYLOAD_IN_SIZE 13

struct cxl_mbox_eh_link_dbg_cfg_in {
	u8 mode;
	__le16 lane_mask;
	u8 rate_mask;
	__le32 timer_us;
	__le32 cap_delay_us;
	u8 max_cap;
} __attribute__((packed));

CXL_EXPORT int cxl_memdev_eh_link_dbg_cfg(struct cxl_memdev *memdev, u8 port_id, u8 op_mode,
	u8 cap_type, u16 lane_mask, u8 rate_mask, u32 timer_us, u32 cap_delay_us, u8 max_cap)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_link_dbg_cfg_in *eh_link_dbg_cfg_in;
	int rc=0;

	u8 modes;
	modes = ((port_id) | (op_mode << 2) | (cap_type <<4));

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_link_dbg_cfg_in = (void *) cmd->send_cmd->in.payload;
	eh_link_dbg_cfg_in->mode = modes;
	eh_link_dbg_cfg_in->lane_mask = cpu_to_le16(lane_mask);
	eh_link_dbg_cfg_in->rate_mask = rate_mask;
	eh_link_dbg_cfg_in->timer_us = cpu_to_le32(timer_us);
	eh_link_dbg_cfg_in->cap_delay_us = cpu_to_le32(cap_delay_us);
	eh_link_dbg_cfg_in->max_cap = max_cap;

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_EH_LINK_DBG_CFG);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP_OPCODE 0XCC07
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP_PAYLOAD_IN_SIZE 1
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP_PAYLOAD_OUT_SIZE 34

struct cxl_mbox_eh_link_dbg_entry_dump_in {
	u8 entry_idx;
} __attribute__((packed));

struct cxl_mbox_eh_link_dbg_entry_dump_out {
	u8 cap_info;
	u8 cap_reason;
	__le32 l2r_reason;
	__le64 start_time;
	__le64 end_time;
	u8 start_rate;
	u8 end_rate;
	u8 start_state;
	u8 end_state;
	__le32 start_status;
	__le32 end_status;
} __attribute__((packed));

struct eh_link_dbg_entry_dump_fields {
	u8 entry_idx;
	u8 entry_num;
};

CXL_EXPORT int cxl_memdev_eh_link_dbg_entry_dump(struct cxl_memdev *memdev, u8 entry_idx)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_link_dbg_entry_dump_in *eh_link_dbg_entry_dump_in;
	struct cxl_mbox_eh_link_dbg_entry_dump_out *eh_link_dbg_entry_dump_out;
	struct eh_link_dbg_entry_dump_fields *cap_info_fields;
	u8 entry_idx_shift = 0;
	u8 entry_num_shift = 4;
	u8 entry_idx_mask = (1 << entry_num_shift) - (1 << entry_idx_shift); // 0-3
	u8 entry_num_mask = 0xff - (1 << entry_num_shift) + 1; // 4-7
	int rc=0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_link_dbg_entry_dump_in = (void *) cmd->send_cmd->in.payload;
	eh_link_dbg_entry_dump_in->entry_idx = entry_idx;

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_EH_LINK_DBG_ENTRY_DUMP);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
	eh_link_dbg_entry_dump_out = (void *)cmd->send_cmd->out.payload;

	cap_info_fields->entry_idx = (eh_link_dbg_entry_dump_out->cap_info & entry_idx_mask) >> entry_idx_shift;
	cap_info_fields->entry_num = (eh_link_dbg_entry_dump_out->cap_info & entry_num_mask) >> entry_num_shift;

	fprintf(stdout, "=========================== EH Link Debug Entry Dump ============================\n");
	fprintf(stdout, "Capture Info (Entry Index): %x\n", cap_info_fields->entry_idx);
	fprintf(stdout, "Capture Info (Entry Num): %x\n", cap_info_fields->entry_num);
	fprintf(stdout, "Capture Reason: %x\n", eh_link_dbg_entry_dump_out->cap_reason);
	fprintf(stdout, "L2R Reason: %x\n", le32_to_cpu(eh_link_dbg_entry_dump_out->l2r_reason));
	fprintf(stdout, "Capture Start Timestamp: %lx\n", le64_to_cpu(eh_link_dbg_entry_dump_out->start_time));
	fprintf(stdout, "Capture End Timestamp: %lx\n", le64_to_cpu(eh_link_dbg_entry_dump_out->end_time));
	fprintf(stdout, "Capture Start Rate: %x\n", eh_link_dbg_entry_dump_out->start_rate);
	fprintf(stdout, "Capture End Rate: %x\n", eh_link_dbg_entry_dump_out->end_rate);
	fprintf(stdout, "Capture Start State: %x\n", eh_link_dbg_entry_dump_out->start_state);
	fprintf(stdout, "Capture End State: %x\n", eh_link_dbg_entry_dump_out->end_state);
	fprintf(stdout, "Capture Start Status: %x\n", le32_to_cpu(eh_link_dbg_entry_dump_out->start_status));
	fprintf(stdout, "Capture End Status: %x\n", le32_to_cpu(eh_link_dbg_entry_dump_out->end_status));
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP_OPCODE 0XCC08
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP_PAYLOAD_IN_SIZE 2
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP_PAYLOAD_OUT_SIZE 59

struct cxl_mbox_eh_link_dbg_lane_dump_in {
	u8 entry_idx;
	u8 lane_idx;
} __attribute__((packed));

struct cxl_mbox_eh_link_dbg_lane_dump_out {
	u8 cap_info;
	u8 pga_gain;
	u8 pga_off2;
	u8 pga_off1;
	u8 cdfe_a2;
	u8 cdfe_a3;
	u8 cdfe_a4;
	u8 cdfe_a5;
	u8 cdfe_a6;
	u8 cdfe_a7;
	u8 cdfe_a8;
	u8 cdfe_a9;
	u8 cdfe_a10;
	u8 zobel_a_gain;
	u8 zobel_b_gain;
	__le16 zobel_dc_offset;
	__le16 udfe_thr_0;
	__le16 udfe_thr_1;
	__le16 dc_offset;
	__le16 median_amp;
	u8 ph_ofs_t;
	__le16 cdru_lock_time;
	__le16 eh_workaround_stat;
	__le16 los_toggle_cnt;
	__le16 adapt_time;
	__le16 cdr_lock_toggle_cnt_0;
	__le16 jat_stat_0;
	__le32 db_err;
	__le32 reg_val0;
	u8 reg_val1;
	__le32 reg_val2;
	__le32 reg_val3;
	__le32 reg_val4;

} __attribute__((packed));

struct eh_link_dbg_cap_info_fields {
	u8 lane_idx;
	u8 entry_idx;
};

struct eh_link_dbg_reg_val0_fields {
	u8 fs_obs;
	u8 lf_obs;
	u8 pre_cursor;
	u8 cursor;
	u8 post_cursor;
	u8 rsvd;
};

struct eh_link_dbg_reg_val1_fields {
	u8 usp_tx_preset;
	u8 dsp_tx_preset;
};

struct eh_link_dbg_reg_val2_fields {
	u8 tx_p1a_d1en;
	u8 tx_p1a_d2en;
	u8 tx_p1a_amp_red;
	u8 tx_p1b_d1en;
	u8 tx_p1b_d2en;
	u8 rsvd1;
};

struct eh_link_dbg_reg_val3_fields {
	u8 tx_p1b_amp_red;
	u8 tx_p2a_d1en;
	u8 tx_p2a_d2en;
	u8 tx_p2a_amp_red;
	u8 rsvd2;
};

struct eh_link_dbg_reg_val4_fields {
	u8 tx_p2b_d1en;
	u8 tx_p2b_d2en;
	u8 tx_p2b_amp_red;
	u8 tx_p3a_d1en;
	u8 rsvd3;
};

CXL_EXPORT int cxl_memdev_eh_link_dbg_lane_dump(struct cxl_memdev *memdev, u8 entry_idx, u8 lane_idx)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_eh_link_dbg_lane_dump_in *eh_link_dbg_lane_dump_in;
	struct cxl_mbox_eh_link_dbg_lane_dump_out *eh_link_dbg_lane_dump_out;
	struct eh_link_dbg_cap_info_fields *cap_info_fields;
	struct eh_link_dbg_reg_val0_fields *reg_val0_fields;
	struct eh_link_dbg_reg_val1_fields *reg_val1_fields;
	struct eh_link_dbg_reg_val2_fields *reg_val2_fields;
	struct eh_link_dbg_reg_val3_fields *reg_val3_fields;
	struct eh_link_dbg_reg_val4_fields *reg_val4_fields;

	int rc=0;
	// Initializing bit shifts and bit masks.

	// Capture Info
	u8 lane_idx_shift = 0;
	u8 entry_idx_shift = 4;
	u8 lane_idx_mask = (1 << entry_idx_shift) - (1 << lane_idx_shift); // 0-3
	u8 entry_idx_mask = 0xff - (1 << entry_idx_shift) + 1; // 4-7

	// register data 0
	u8 fs_obs_shift = 0;
	u8 lf_obs_shift = 6;
	u8 pre_cursor_shift = 12;
	u8 cursor_shift = 18;
	u8 post_cursor_shift = 24;
	u8 rsvd_shift = 30;
	u32 fs_obs_mask = (1 << lf_obs_shift) - (1 << fs_obs_shift); // 0-5
	u32 lf_obs_mask = (1 << pre_cursor_shift) - (1 << lf_obs_shift); // 6-11
	u32 pre_cursor_mask = (1 << cursor_shift) - (1 << pre_cursor_shift); // 12-17
	u32 cursor_mask = (1 << post_cursor_shift) - (1 << cursor_shift); //18-23
	u32 post_cursor_mask = (1 << rsvd_shift) - (1 << post_cursor_shift); //24-29

	// register data 1
	u8 usp_tx_preset_shift = 0;
	u8 dsp_tx_preset_shift = 4;
	u32 usp_tx_preset_mask = (1 << dsp_tx_preset_shift) - (1<< usp_tx_preset_shift); // 0-3
	u32 dsp_tx_preset_mask = 0xff - (1 << dsp_tx_preset_shift); // 4-7

	// register data 2
	u8 tx_p1a_d1en_shift = 0;
	u8 tx_p1a_d2en_shift = 6;
	u8 tx_p1a_amp_red_shift = 12;
	u8 tx_p1b_d1en_shift = 18;
	u8 tx_p1b_d2en_shift = 24;
	u8 rsvd1_shift = 30;
	u32 tx_p1a_d1en_mask = (1 << tx_p1a_d2en_shift) - (1 << tx_p1a_d1en_shift);
	u32 tx_p1a_d2en_mask = (1 << tx_p1a_amp_red_shift) - (1 << tx_p1a_d2en_shift);
	u32 tx_p1a_amp_red_mask = (1 << tx_p1b_d1en_shift) - (1 << tx_p1a_amp_red_shift);
	u32 tx_p1b_d1en_mask = (1 << tx_p1b_d2en_shift) - (1 << tx_p1b_d1en_shift);
	u32 tx_p1b_d2en_mask = (1 << rsvd1_shift) - (1 << tx_p1b_d2en_shift);

	// register data 3
	u8 tx_p1b_amp_red_shift = 0;
	u8 tx_p2a_d1en_shift = 6;
	u8 tx_p2a_d2en_shift = 12;
	u8 tx_p2a_amp_red_shift = 18;
	u8 rsvd2_shift = 24;
	u32 tx_p1b_amp_red_mask = (1 << tx_p2a_d1en_shift) - (1 << tx_p1b_amp_red_shift);
	u32 tx_p2a_d1en_mask = (1 << tx_p2a_d2en_shift) - (1 << tx_p2a_d1en_shift);
	u32 tx_p2a_d2en_mask = (1 << tx_p2a_amp_red_shift) - (1 << tx_p2a_d2en_shift);
	u32 tx_p2a_amp_red_mask = (1 << rsvd2_shift) - (1 << tx_p2a_amp_red_shift);

	// register data 4
	u8 tx_p2b_d1en_shift = 0;
	u8 tx_p2b_d2en_shift = 6;
	u8 tx_p2b_amp_red_shift = 12;
	u8 tx_p3a_d1en_shift = 18;
	u8 rsvd3_shift = 24;
	u32 tx_p2b_d1en_mask = (1 << tx_p2b_d2en_shift) - (1 << tx_p2b_d1en_shift);
	u32 tx_p2b_d2en_mask = (1 << tx_p2b_amp_red_shift) - (1 << tx_p2b_d2en_shift);
	u32 tx_p2b_amp_red_mask = (1 << tx_p3a_d1en_shift) - (1 << tx_p2b_amp_red_shift);
	u32 tx_p3a_d1en_mask = (1 << rsvd3_shift) - (1 << tx_p3a_d1en_shift);

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	eh_link_dbg_lane_dump_in = (void *) cmd->send_cmd->in.payload;
	eh_link_dbg_lane_dump_in->entry_idx = entry_idx;
	eh_link_dbg_lane_dump_in->lane_idx = lane_idx;

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_EH_LINK_DBG_LANE_DUMP);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");
	eh_link_dbg_lane_dump_out = (void *)cmd->send_cmd->out.payload;

	cap_info_fields->lane_idx = (eh_link_dbg_lane_dump_out->cap_info & lane_idx_mask) >> lane_idx_shift;
	cap_info_fields->entry_idx = (eh_link_dbg_lane_dump_out->cap_info & entry_idx_mask) >> entry_idx_shift;

	reg_val0_fields->fs_obs = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val0) & fs_obs_mask) >> fs_obs_shift;
	reg_val0_fields->lf_obs = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val0) & lf_obs_mask) >> lf_obs_shift;
	reg_val0_fields->pre_cursor = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val0) & pre_cursor_mask) >> pre_cursor_shift;
	reg_val0_fields->cursor = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val0) & cursor_mask) >> cursor_shift;
	reg_val0_fields->post_cursor = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val0) & post_cursor_mask) >> post_cursor_shift;

	reg_val1_fields->usp_tx_preset = (eh_link_dbg_lane_dump_out->reg_val1 & usp_tx_preset_mask) >> usp_tx_preset_shift;
	reg_val1_fields->dsp_tx_preset = (eh_link_dbg_lane_dump_out->reg_val1 & dsp_tx_preset_mask) >> dsp_tx_preset_shift;

	reg_val2_fields->tx_p1a_d1en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val2) & tx_p1a_d1en_mask) >> tx_p1a_d1en_shift;
	reg_val2_fields->tx_p1a_d2en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val2) & tx_p1a_d2en_mask) >> tx_p1a_d2en_shift;
	reg_val2_fields->tx_p1a_amp_red = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val2) & tx_p1a_amp_red_mask) >> tx_p1a_amp_red_shift;
	reg_val2_fields->tx_p1b_d1en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val2) & tx_p1b_d1en_mask) >> tx_p1b_d1en_shift;
	reg_val2_fields->tx_p1b_d2en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val2) & tx_p1b_d2en_mask) >> tx_p1b_d2en_shift;

	reg_val3_fields->tx_p1b_amp_red = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val3) & tx_p1b_amp_red_mask) >> tx_p1b_amp_red_shift;
	reg_val3_fields->tx_p2a_d1en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val3) & tx_p2a_d1en_mask) >> tx_p2a_d1en_shift;
	reg_val3_fields->tx_p2a_d2en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val3) & tx_p2a_d2en_mask) >> tx_p2a_d2en_shift;
	reg_val3_fields->tx_p2a_amp_red = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val3) & tx_p2a_amp_red_mask) >> tx_p2a_amp_red_shift;

	reg_val4_fields->tx_p2b_d1en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val4) & tx_p2b_d1en_mask) >> tx_p2b_d1en_shift;
	reg_val4_fields->tx_p2b_d2en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val4) & tx_p2b_d2en_mask) >> tx_p2b_d2en_shift;
	reg_val4_fields->tx_p2b_amp_red = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val4) & tx_p2b_amp_red_mask) >> tx_p2b_amp_red_shift;
	reg_val4_fields->tx_p3a_d1en = (le32_to_cpu(eh_link_dbg_lane_dump_out->reg_val4) & tx_p3a_d1en_mask) >> tx_p3a_d1en_shift;

	fprintf(stdout, "=========================== EH Link Debug Lane Dump ============================\n");
	fprintf(stdout, "Capture Lane: %x\n", cap_info_fields->lane_idx);
	fprintf(stdout, "Capture Entry Index: %x\n", cap_info_fields->entry_idx);
	fprintf(stdout, "PGA Gain: %x\n", eh_link_dbg_lane_dump_out->pga_gain);
	fprintf(stdout, "PGA offset 2: %x\n", eh_link_dbg_lane_dump_out->pga_off2);
	fprintf(stdout, "PGA offset 1: %x\n", eh_link_dbg_lane_dump_out->pga_off1);
	fprintf(stdout, "CDFE A2: %x\n", eh_link_dbg_lane_dump_out->cdfe_a2);
	fprintf(stdout, "CDFE A3: %x\n", eh_link_dbg_lane_dump_out->cdfe_a3);
	fprintf(stdout, "CDFE A4: %x\n", eh_link_dbg_lane_dump_out->cdfe_a4);
	fprintf(stdout, "CDFE A5: %x\n", eh_link_dbg_lane_dump_out->cdfe_a5);
	fprintf(stdout, "CDFE A6: %x\n", eh_link_dbg_lane_dump_out->cdfe_a6);
	fprintf(stdout, "CDFE A7: %x\n", eh_link_dbg_lane_dump_out->cdfe_a7);
	fprintf(stdout, "CDFE A8: %x\n", eh_link_dbg_lane_dump_out->cdfe_a8);
	fprintf(stdout, "CDFE A9: %x\n", eh_link_dbg_lane_dump_out->cdfe_a9);
	fprintf(stdout, "CDFE A10: %x\n", eh_link_dbg_lane_dump_out->cdfe_a10);
	fprintf(stdout, "Zobel A Gain: %x\n", eh_link_dbg_lane_dump_out->zobel_a_gain);
	fprintf(stdout, "Zobel B Gain: %x\n", eh_link_dbg_lane_dump_out->zobel_b_gain);
	fprintf(stdout, "Zobel DC Offset: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->zobel_dc_offset));
	fprintf(stdout, "UDFE_THR_0: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->udfe_thr_0));
	fprintf(stdout, "UDFE_THR_1: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->udfe_thr_1));
	fprintf(stdout, "DC_OFFSET: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->dc_offset));
	fprintf(stdout, "MEDIAN_AMP: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->median_amp));
	fprintf(stdout, "PH_OFS_T: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->ph_ofs_t));
	fprintf(stdout, "CDRU lock time: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->cdru_lock_time));
	fprintf(stdout, "EH Workaround Status: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->eh_workaround_stat));
	fprintf(stdout, "LOS toggle count: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->los_toggle_cnt));
	fprintf(stdout, "Adaptation time: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->adapt_time));
	fprintf(stdout, "CDR lock toggle count (arg = 0): %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->cdr_lock_toggle_cnt_0));
	fprintf(stdout, "JAT status (arg = 0): %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->jat_stat_0));
	fprintf(stdout, "dorbell error: %x\n", le16_to_cpu(eh_link_dbg_lane_dump_out->db_err));
	fprintf(stdout, "==== EH register 0 value capture ====\n");
	fprintf(stdout, "FS from PIPE interface: %x\n", reg_val0_fields->fs_obs);
	fprintf(stdout, "LF from PIPE interface: %x\n", reg_val0_fields->lf_obs);
	fprintf(stdout, "Pre-cursor value from PIPE interface: %x\n", reg_val0_fields->pre_cursor);
	fprintf(stdout, "Cursor value from PIPE interface: %x\n", reg_val0_fields->cursor);
	fprintf(stdout, "Post-cursor value from PIPE interface: %x\n", reg_val0_fields->post_cursor);
	fprintf(stdout, "==== EH register 1 value capture ====\n");
	fprintf(stdout, "US_PORT_TX_PRESET for current link rate: %x\n", reg_val1_fields->usp_tx_preset);
	fprintf(stdout, "DS_PORT_TX_PRESET for current link rate: %x\n", reg_val1_fields->dsp_tx_preset);
	fprintf(stdout, "==== EH register 2 value capture ====\n");
	fprintf(stdout, "TX_P1A_D1EN: %x\n", reg_val2_fields->tx_p1a_d1en);
	fprintf(stdout, "TX_P1A_D2EN: %x\n", reg_val2_fields->tx_p1a_d2en);
	fprintf(stdout, "TX_P1A_AMP_RED: %x\n", reg_val2_fields->tx_p1a_amp_red);
	fprintf(stdout, "TX_P1B_D1EN: %x\n", reg_val2_fields->tx_p1b_d1en);
	fprintf(stdout, "TX_P1B_D2EN: %x\n", reg_val2_fields->tx_p1b_d2en);
	fprintf(stdout, "==== EH register 3 value capture ====\n");
	fprintf(stdout, "TX_P1B_AMP_RED: %x\n", reg_val3_fields->tx_p1b_amp_red);
	fprintf(stdout, "TX_P2A_D1EN: %x\n", reg_val3_fields->tx_p2a_d1en);
	fprintf(stdout, "TX_P2A_D2EN: %x\n", reg_val3_fields->tx_p2a_d2en);
	fprintf(stdout, "TX_P2A_AMP_RED: %x\n", reg_val3_fields->tx_p2a_amp_red);
	fprintf(stdout, "==== EH register 4 value capture ====\n");
	fprintf(stdout, "TX_P2B_D1EN: %x\n", reg_val4_fields->tx_p2b_d1en);
	fprintf(stdout, "TX_P2B_D2EN: %x\n", reg_val4_fields->tx_p2b_d2en);
	fprintf(stdout, "TX_P2B_AMP_RED: %x\n", reg_val4_fields->tx_p2b_amp_red);
	fprintf(stdout, "TX_P3A_D1EN: %x\n", reg_val4_fields->tx_p3a_d1en);
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET_OPCODE 0XCC09
#define CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET_PAYLOAD_IN_SIZE 0

CXL_EXPORT int cxl_memdev_eh_link_dbg_reset(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	int rc=0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET_OPCODE);
	if(!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}
	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}
	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id,
	CXL_MEM_COMMAND_ID_EH_LINK_DBG_RESET);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

	fprintf(stdout, "EH Link Reset Completed \n");
out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET_OPCODE 49671
#define CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET_PAYLOAD_IN_SIZE 7

struct cxl_mbox_fbist_stopconfig_set_in {
	__le32 fbist_id;
	u8 stop_on_wresp;
	u8 stop_on_rresp;
	u8 stop_on_rdataerr;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_stopconfig_set(struct cxl_memdev *memdev,
	u32 fbist_id, u8 stop_on_wresp, u8 stop_on_rresp, u8 stop_on_rdataerr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_stopconfig_set_in *fbist_stopconfig_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_stopconfig_set_in = (void *) cmd->send_cmd->in.payload;

	fbist_stopconfig_set_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_stopconfig_set_in->stop_on_wresp = stop_on_wresp;
	fbist_stopconfig_set_in->stop_on_rresp = stop_on_rresp;
	fbist_stopconfig_set_in->stop_on_rdataerr = stop_on_rdataerr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_STOPCONFIG_SET);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET_OPCODE 49672
#define CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET_PAYLOAD_IN_SIZE 16

struct cxl_mbox_fbist_cyclecount_set_in {
	__le32 fbist_id;
	u8 txg_nr;
	u8 rsvd[3];
	__le64 cyclecount;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_cyclecount_set(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr, u64 cyclecount)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_cyclecount_set_in *fbist_cyclecount_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_cyclecount_set_in = (void *) cmd->send_cmd->in.payload;

	fbist_cyclecount_set_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_cyclecount_set_in->txg_nr = txg_nr;
	fbist_cyclecount_set_in->cyclecount = cpu_to_le64(cyclecount);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_CYCLECOUNT_SET);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_RESET_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_RESET_SET_OPCODE 49673
#define CXL_MEM_COMMAND_ID_FBIST_RESET_SET_PAYLOAD_IN_SIZE 6

struct cxl_mbox_fbist_reset_set_in {
	__le32 fbist_id;
	u8 txg0_reset;
	u8 txg1_reset;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_reset_set(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg0_reset, u8 txg1_reset)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_reset_set_in *fbist_reset_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_RESET_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_RESET_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_reset_set_in = (void *) cmd->send_cmd->in.payload;

	fbist_reset_set_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_reset_set_in->txg0_reset = txg0_reset;
	fbist_reset_set_in->txg1_reset = txg1_reset;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_RESET_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_RESET_SET);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_RUN_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_RUN_SET_OPCODE 49674
#define CXL_MEM_COMMAND_ID_FBIST_RUN_SET_PAYLOAD_IN_SIZE 6

struct cxl_mbox_fbist_run_set_in {
	__le32 fbist_id;
	u8 txg0_run;
	u8 txg1_run;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_run_set(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg0_run, u8 txg1_run)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_run_set_in *fbist_run_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_RUN_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_RUN_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_run_set_in = (void *) cmd->send_cmd->in.payload;

	fbist_run_set_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_run_set_in->txg0_run = txg0_run;
	fbist_run_set_in->txg1_run = txg1_run;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_RUN_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_RUN_SET);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_RUN_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_RUN_GET_OPCODE 49675
#define CXL_MEM_COMMAND_ID_FBIST_RUN_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_FBIST_RUN_GET_PAYLOAD_OUT_SIZE 2

struct cxl_mbox_fbist_run_get_in {
	__le32 fbist_id;
}  __attribute__((packed));

struct cxl_mbox_fbist_run_get_out {
	u8 txg0_run;
	u8 txg1_run;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_run_get(struct cxl_memdev *memdev,
	u32 fbist_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_run_get_in *fbist_run_get_in;
	struct cxl_mbox_fbist_run_get_out *fbist_run_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_RUN_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_RUN_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_run_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_run_get_in->fbist_id = cpu_to_le32(fbist_id);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_RUN_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_RUN_GET);
		return -EINVAL;
	}

	fbist_run_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================== read run flags of txg[0|1] ==========================\n");
	fprintf(stdout, "TXG0 Run: %x\n", fbist_run_get_out->txg0_run);
	fprintf(stdout, "TXG1 Run: %x\n", fbist_run_get_out->txg1_run);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET_OPCODE 49680
#define CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET_PAYLOAD_IN_SIZE 5
#define CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET_PAYLOAD_OUT_SIZE 2

struct cxl_mbox_fbist_xfer_rem_cnt_get_in {
	__le32 fbist_id;
	u8 thread_nr;
}  __attribute__((packed));

struct cxl_mbox_fbist_xfer_rem_cnt_get_out {
	__le16 xfer_rem;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_xfer_rem_cnt_get(struct cxl_memdev *memdev,
	u32 fbist_id, u8 thread_nr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_xfer_rem_cnt_get_in *fbist_xfer_rem_cnt_get_in;
	struct cxl_mbox_fbist_xfer_rem_cnt_get_out *fbist_xfer_rem_cnt_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_xfer_rem_cnt_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_xfer_rem_cnt_get_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_xfer_rem_cnt_get_in->thread_nr = thread_nr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_XFER_REM_CNT_GET);
		return -EINVAL;
	}

	fbist_xfer_rem_cnt_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "================== read a thread's remaining transfer counts ===================\n");
	fprintf(stdout, "XFER Remaining: %x\n", le16_to_cpu(fbist_xfer_rem_cnt_get_out->xfer_rem));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET_OPCODE 49681
#define CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET_PAYLOAD_OUT_SIZE 128

struct cxl_mbox_fbist_last_exp_read_data_get_in {
	__le32 fbist_id;
}  __attribute__((packed));

struct cxl_mbox_fbist_last_exp_read_data_get_out {
	__le32 last_rd_data[16];
	__le32 exp_rd_data[16];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_last_exp_read_data_get(struct cxl_memdev *memdev,
	u32 fbist_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_last_exp_read_data_get_in *fbist_last_exp_read_data_get_in;
	struct cxl_mbox_fbist_last_exp_read_data_get_out *fbist_last_exp_read_data_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_last_exp_read_data_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_last_exp_read_data_get_in->fbist_id = cpu_to_le32(fbist_id);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_LAST_EXP_READ_DATA_GET);
		return -EINVAL;
	}

	fbist_last_exp_read_data_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================= reads last and expected data =========================\n");
	fprintf(stdout, "last_rd_data: ");
	for (int i = 0; i < 16; i++) {
		fprintf(stdout, "last_rd_data[%d]: %x\n", i, le32_to_cpu(fbist_last_exp_read_data_get_out->last_rd_data[i]));
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "exp_rd_data: ");
	for (int i = 0; i < 16; i++) {
		fprintf(stdout, "exp_rd_data[%d]: %x\n", i, le32_to_cpu(fbist_last_exp_read_data_get_out->exp_rd_data[i]));
	}
	fprintf(stdout, "\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET_OPCODE 49682
#define CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET_PAYLOAD_IN_SIZE 5
#define CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_fbist_curr_cycle_cnt_get_in {
	__le32 fbist_id;
	u8 txg_nr;
}  __attribute__((packed));

struct cxl_mbox_fbist_curr_cycle_cnt_get_out {
	__le64 curr_cycle_cnt;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_curr_cycle_cnt_get(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_curr_cycle_cnt_get_in *fbist_curr_cycle_cnt_get_in;
	struct cxl_mbox_fbist_curr_cycle_cnt_get_out *fbist_curr_cycle_cnt_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_curr_cycle_cnt_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_curr_cycle_cnt_get_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_curr_cycle_cnt_get_in->txg_nr = txg_nr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_CURR_CYCLE_CNT_GET);
		return -EINVAL;
	}

	fbist_curr_cycle_cnt_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "======================= read a txg's current cycle count =======================\n");
	fprintf(stdout, "Current Cycle Count: %lx\n", le64_to_cpu(fbist_curr_cycle_cnt_get_out->curr_cycle_cnt));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET_OPCODE 49683
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET_PAYLOAD_IN_SIZE 6
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET_PAYLOAD_OUT_SIZE 4

struct cxl_mbox_fbist_thread_status_get_in {
	__le32 fbist_id;
	u8 txg_nr;
	u8 thread_nr;
}  __attribute__((packed));

struct cxl_mbox_fbist_thread_status_get_out {
	u8 thread_state;
	u8 rsvd;
	__le16 curr_thread_desc_index;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_thread_status_get(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr, u8 thread_nr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_thread_status_get_in *fbist_thread_status_get_in;
	struct cxl_mbox_fbist_thread_status_get_out *fbist_thread_status_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_thread_status_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_thread_status_get_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_thread_status_get_in->txg_nr = txg_nr;
	fbist_thread_status_get_in->thread_nr = thread_nr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_THREAD_STATUS_GET);
		return -EINVAL;
	}

	fbist_thread_status_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================== read a txg's thread status ==========================\n");
	fprintf(stdout, "Thread State: %x\n", fbist_thread_status_get_out->thread_state);
	fprintf(stdout, "curr_thread_desc_index: %x\n", le16_to_cpu(fbist_thread_status_get_out->curr_thread_desc_index));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET_OPCODE 49684
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET_PAYLOAD_IN_SIZE 6
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_fbist_thread_trans_cnt_get_in {
	__le32 fbist_id;
	u8 txg_nr;
	u8 thread_nr;
}  __attribute__((packed));

struct cxl_mbox_fbist_thread_trans_cnt_get_out {
	__le64 transaction_cnt;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_thread_trans_cnt_get(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr, u8 thread_nr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_thread_trans_cnt_get_in *fbist_thread_trans_cnt_get_in;
	struct cxl_mbox_fbist_thread_trans_cnt_get_out *fbist_thread_trans_cnt_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_thread_trans_cnt_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_thread_trans_cnt_get_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_thread_trans_cnt_get_in->txg_nr = txg_nr;
	fbist_thread_trans_cnt_get_in->thread_nr = thread_nr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_THREAD_TRANS_CNT_GET);
		return -EINVAL;
	}

	fbist_thread_trans_cnt_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "==================== read a txg's thread transaction count =====================\n");
	fprintf(stdout, "Transaction Count: %lx\n", le64_to_cpu(fbist_thread_trans_cnt_get_out->transaction_cnt));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET_OPCODE 49685
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET_PAYLOAD_IN_SIZE 6
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_fbist_thread_bandwidth_get_in {
	__le32 fbist_id;
	u8 txg_nr;
	u8 thread_nr;
}  __attribute__((packed));

struct cxl_mbox_fbist_thread_bandwidth_get_out {
	__le32 read_bw_cnt;
	__le32 write_bw_cnt;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_thread_bandwidth_get(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr, u8 thread_nr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_thread_bandwidth_get_in *fbist_thread_bandwidth_get_in;
	struct cxl_mbox_fbist_thread_bandwidth_get_out *fbist_thread_bandwidth_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_thread_bandwidth_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_thread_bandwidth_get_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_thread_bandwidth_get_in->txg_nr = txg_nr;
	fbist_thread_bandwidth_get_in->thread_nr = thread_nr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_THREAD_BANDWIDTH_GET);
		return -EINVAL;
	}

	fbist_thread_bandwidth_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "================= read a txg's thread rd/wr bandwidth counters =================\n");
	fprintf(stdout, "Read BW Count: %x\n", le32_to_cpu(fbist_thread_bandwidth_get_out->read_bw_cnt));
	fprintf(stdout, "Write BW Count: %x\n", le32_to_cpu(fbist_thread_bandwidth_get_out->write_bw_cnt));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET_OPCODE 49686
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET_PAYLOAD_IN_SIZE 6
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_fbist_thread_latency_get_in {
	__le32 fbist_id;
	u8 txg_nr;
	u8 thread_nr;
}  __attribute__((packed));

struct cxl_mbox_fbist_thread_latency_get_out {
	__le32 read_latency_cnt;
	__le32 write_latency_cnt;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_thread_latency_get(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr, u8 thread_nr)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_thread_latency_get_in *fbist_thread_latency_get_in;
	struct cxl_mbox_fbist_thread_latency_get_out *fbist_thread_latency_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_thread_latency_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_thread_latency_get_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_thread_latency_get_in->txg_nr = txg_nr;
	fbist_thread_latency_get_in->thread_nr = thread_nr;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_THREAD_LATENCY_GET);
		return -EINVAL;
	}

	fbist_thread_latency_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "================== read a txg's thread rd/wr latency counters ==================\n");
	fprintf(stdout, "Read Latency Count: %x\n", le32_to_cpu(fbist_thread_latency_get_out->read_latency_cnt));
	fprintf(stdout, "Write Latency Count: %x\n", le32_to_cpu(fbist_thread_latency_get_out->write_latency_cnt));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET_OPCODE 49687
#define CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET_PAYLOAD_IN_SIZE 10

struct cxl_mbox_fbist_thread_perf_mon_set_in {
	__le32 fbist_id;
	u8 txg_nr;
	u8 thread_nr;
	u8 pmon_preset_en;
	u8 pmon_clear_en;
	u8 pmon_rollover;
	u8 pmon_thread_lclk;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_thread_perf_mon_set(struct cxl_memdev *memdev,
	u32 fbist_id, u8 txg_nr, u8 thread_nr, u8 pmon_preset_en, u8 pmon_clear_en,
	u8 pmon_rollover, u8 pmon_thread_lclk)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_thread_perf_mon_set_in *fbist_thread_perf_mon_set_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_thread_perf_mon_set_in = (void *) cmd->send_cmd->in.payload;

	fbist_thread_perf_mon_set_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_thread_perf_mon_set_in->txg_nr = txg_nr;
	fbist_thread_perf_mon_set_in->thread_nr = thread_nr;
	fbist_thread_perf_mon_set_in->pmon_preset_en = pmon_preset_en;
	fbist_thread_perf_mon_set_in->pmon_clear_en = pmon_clear_en;
	fbist_thread_perf_mon_set_in->pmon_rollover = pmon_rollover;
	fbist_thread_perf_mon_set_in->pmon_thread_lclk = pmon_thread_lclk;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_THREAD_PERF_MON_SET);
		return -EINVAL;
	}
	fprintf(stdout, "Command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET_OPCODE 49688
#define CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET_PAYLOAD_OUT_SIZE 3

struct cxl_mbox_fbist_top_read_status0_get_in {
	__le32 fbist_id;
}  __attribute__((packed));

struct cxl_mbox_fbist_top_read_status0_get_out {
	__le16 tag_id_err_idx;
	u8 thread_err_idx;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_top_read_status0_get(struct cxl_memdev *memdev,
	u32 fbist_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_top_read_status0_get_in *fbist_top_read_status0_get_in;
	struct cxl_mbox_fbist_top_read_status0_get_out *fbist_top_read_status0_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_top_read_status0_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_top_read_status0_get_in->fbist_id = cpu_to_le32(fbist_id);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_TOP_READ_STATUS0_GET);
		return -EINVAL;
	}

	fbist_top_read_status0_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================== read the top read status0 ===========================\n");
	fprintf(stdout, "tag_id_err_idx: %x\n", le16_to_cpu(fbist_top_read_status0_get_out->tag_id_err_idx));
	fprintf(stdout, "thread_err_idx: %x\n", fbist_top_read_status0_get_out->thread_err_idx);

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET_OPCODE 49689
#define CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET_PAYLOAD_OUT_SIZE 12

struct cxl_mbox_fbist_top_err_cnt_get_in {
	__le32 fbist_id;
}  __attribute__((packed));

struct cxl_mbox_fbist_top_err_cnt_get_out {
	__le32 rdata_err_cnt;
	__le32 rresp_err_cnt;
	__le32 wresp_err_cnt;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_top_err_cnt_get(struct cxl_memdev *memdev,
	u32 fbist_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_top_err_cnt_get_in *fbist_top_err_cnt_get_in;
	struct cxl_mbox_fbist_top_err_cnt_get_out *fbist_top_err_cnt_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_top_err_cnt_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_top_err_cnt_get_in->fbist_id = cpu_to_le32(fbist_id);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_TOP_ERR_CNT_GET);
		return -EINVAL;
	}

	fbist_top_err_cnt_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "===== read read-dataframe, read-response and write-response error counters =====\n");
	fprintf(stdout, "Read Data Error Count: %x\n", le32_to_cpu(fbist_top_err_cnt_get_out->rdata_err_cnt));
	fprintf(stdout, "Read Response Error Count: %x\n", le32_to_cpu(fbist_top_err_cnt_get_out->rresp_err_cnt));
	fprintf(stdout, "Write Response Error Count: %x\n", le32_to_cpu(fbist_top_err_cnt_get_out->wresp_err_cnt));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET_OPCODE 49690
#define CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET_PAYLOAD_IN_SIZE 4
#define CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET_PAYLOAD_OUT_SIZE 8

struct cxl_mbox_fbist_last_read_addr_get_in {
	__le32 fbist_id;
}  __attribute__((packed));

struct cxl_mbox_fbist_last_read_addr_get_out {
	__le64 last_read_addr;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_fbist_last_read_addr_get(struct cxl_memdev *memdev,
	u32 fbist_id)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_last_read_addr_get_in *fbist_last_read_addr_get_in;
	struct cxl_mbox_fbist_last_read_addr_get_out *fbist_last_read_addr_get_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_last_read_addr_get_in = (void *) cmd->send_cmd->in.payload;

	fbist_last_read_addr_get_in->fbist_id = cpu_to_le32(fbist_id);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_LAST_READ_ADDR_GET);
		return -EINVAL;
	}

	fbist_last_read_addr_get_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================== read the last read address ==========================\n");
	fprintf(stdout, "last_read_addr: %lx\n", le64_to_cpu(fbist_last_read_addr_get_out->last_read_addr));

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA_OPCODE 49712
#define CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA_PAYLOAD_IN_SIZE 24

struct cxl_mbox_fbist_test_simpledata_in {
	__le32 fbist_id;
	u8 test_nr;
	u8 rsvd[3];
	__le64 start_address;
	__le64 num_bytes;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_test_simpledata(struct cxl_memdev *memdev,
	u32 fbist_id, u8 test_nr, u64 start_address, u64 num_bytes)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_test_simpledata_in *fbist_test_simpledata_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_test_simpledata_in = (void *) cmd->send_cmd->in.payload;

	fbist_test_simpledata_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_test_simpledata_in->test_nr = test_nr;
	fbist_test_simpledata_in->start_address = cpu_to_le64(start_address);
	fbist_test_simpledata_in->num_bytes = cpu_to_le64(num_bytes);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_TEST_SIMPLEDATA);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST_OPCODE 49713
#define CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST_PAYLOAD_IN_SIZE 28

struct cxl_mbox_fbist_test_addresstest_in {
	__le32 fbist_id;
	u8 test_nr;
	u8 rsvd[3];
	__le64 start_address;
	__le64 num_bytes;
	__le32 seed;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_test_addresstest(struct cxl_memdev *memdev,
	u32 fbist_id, u8 test_nr, u64 start_address, u64 num_bytes, u32 seed)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_test_addresstest_in *fbist_test_addresstest_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_test_addresstest_in = (void *) cmd->send_cmd->in.payload;

	fbist_test_addresstest_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_test_addresstest_in->test_nr = test_nr;
	fbist_test_addresstest_in->start_address = cpu_to_le64(start_address);
	fbist_test_addresstest_in->num_bytes = cpu_to_le64(num_bytes);
	fbist_test_addresstest_in->seed = cpu_to_le32(seed);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_TEST_ADDRESSTEST);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION_OPCODE 49714
#define CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION_PAYLOAD_IN_SIZE 28

struct cxl_mbox_fbist_test_movinginversion_in {
	__le32 fbist_id;
	u8 test_nr;
	u8 phase_nr;
	__le16 rsvd;
	__le64 start_address;
	__le64 num_bytes;
	__le32 ddrpage_size;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_test_movinginversion(struct cxl_memdev *memdev,
	u32 fbist_id, u8 test_nr, u8 phase_nr, u64 start_address, u64 num_bytes,
	u32 ddrpage_size)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_test_movinginversion_in *fbist_test_movinginversion_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_test_movinginversion_in = (void *) cmd->send_cmd->in.payload;

	fbist_test_movinginversion_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_test_movinginversion_in->test_nr = test_nr;
	fbist_test_movinginversion_in->phase_nr = phase_nr;
	fbist_test_movinginversion_in->start_address = cpu_to_le64(start_address);
	fbist_test_movinginversion_in->num_bytes = cpu_to_le64(num_bytes);
	fbist_test_movinginversion_in->ddrpage_size = cpu_to_le32(ddrpage_size);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_TEST_MOVINGINVERSION);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE_OPCODE 49715
#define CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE_PAYLOAD_IN_SIZE 36

struct cxl_mbox_fbist_test_randomsequence_in {
	__le32 fbist_id;
	u8 phase_nr;
	u8 rsvd[3];
	__le64 start_address;
	__le64 num_bytes;
	__le32 ddrpage_size;
	__le32 seed_dr0;
	__le32 seed_dr1;
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_fbist_test_randomsequence(struct cxl_memdev *memdev,
	u32 fbist_id, u8 phase_nr, u64 start_address, u64 num_bytes, u32 ddrpage_size,
	u32 seed_dr0, u32 seed_dr1)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_fbist_test_randomsequence_in *fbist_test_randomsequence_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	fbist_test_randomsequence_in = (void *) cmd->send_cmd->in.payload;

	fbist_test_randomsequence_in->fbist_id = cpu_to_le32(fbist_id);
	fbist_test_randomsequence_in->phase_nr = phase_nr;
	fbist_test_randomsequence_in->start_address = cpu_to_le64(start_address);
	fbist_test_randomsequence_in->num_bytes = cpu_to_le64(num_bytes);
	fbist_test_randomsequence_in->ddrpage_size = cpu_to_le32(ddrpage_size);
	fbist_test_randomsequence_in->seed_dr0 = cpu_to_le32(seed_dr0);
	fbist_test_randomsequence_in->seed_dr1 = cpu_to_le32(seed_dr1);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_FBIST_TEST_RANDOMSEQUENCE);
		return -EINVAL;
	}
	fprintf(stdout, "command completed successfully\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_CONF_READ CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_CONF_READ_OPCODE 52992
#define CXL_MEM_COMMAND_ID_CONF_READ_PAYLOAD_IN_SIZE 8
#define CXL_MEM_COMMAND_ID_CONF_READ_PAYLOAD_OUT_SIZE 4 // varies

struct cxl_mbox_conf_read_in {
	__le32 offset;
	__le32 length;
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_conf_read(struct cxl_memdev *memdev,
	u32 offset, u32 length)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_conf_read_in *conf_read_in;
	u8 *conf_read_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_CONF_READ_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_CONF_READ_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	conf_read_in = (void *) cmd->send_cmd->in.payload;

	conf_read_in->offset = cpu_to_le32(offset);
	conf_read_in->length = cpu_to_le32(length);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_CONF_READ) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_CONF_READ);
		return -EINVAL;
	}

	fprintf(stdout, "command completed successfully\n");
	conf_read_out = (u8*)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== Read configuration file ============================\n");
	fprintf(stdout, "Output Payload:");
	for(int i=0; i<cmd->send_cmd->out.size; i++){
		if (i % 16 == 0)
		{
			fprintf(stdout, "\n%04x  %02x ", i+offset, conf_read_out[i]);
		}
		else
		{
			fprintf(stdout, "%02x ", conf_read_out[i]);
		}
	}
	fprintf(stdout, "\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_HCT_GET_CONFIG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_GET_CONFIG_OPCODE 50689
#define CXL_MEM_COMMAND_ID_HCT_GET_CONFIG_PAYLOAD_IN_SIZE 1
#define CXL_MEM_COMMAND_ID_HCT_GET_CONFIG_PAYLOAD_OUT_SIZE 132
#define HCT_GET_CONFIG_FIXED_PAYLOAD_OUT_SIZE 4
#define TRIG_CONFIG_PACKET_SIZE 4

struct cxl_mbox_hct_get_config_in {
	u8 hct_inst;
}  __attribute__((packed));

struct cxl_mbox_hct_get_config_out {
	u8 post_trig_depth;
	u8 ignore_valid;
	u8 rsvd;
	u8 rsvd3;
	__le32 trig_config[128];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_hct_get_config(struct cxl_memdev *memdev,
	u8 hct_inst)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_hct_get_config_in *hct_get_config_in;
	struct cxl_mbox_hct_get_config_out *hct_get_config_out;
	int rc = 0;
	int trig_config_size;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_GET_CONFIG_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_HCT_GET_CONFIG_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	hct_get_config_in = (void *) cmd->send_cmd->in.payload;

	hct_get_config_in->hct_inst = hct_inst;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_GET_CONFIG) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_GET_CONFIG);
		return -EINVAL;
	}

	hct_get_config_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "==================== get hif/cxl trace buffer configuration ====================\n");
	fprintf(stdout, "Post Trigger Depth: %x\n", hct_get_config_out->post_trig_depth);
	fprintf(stdout, "Ignore Valid: %x\n", hct_get_config_out->ignore_valid);
	// OPL size
	trig_config_size = (cmd->send_cmd->out.size - HCT_GET_CONFIG_FIXED_PAYLOAD_OUT_SIZE) / TRIG_CONFIG_PACKET_SIZE;
	for(int i=0; i<trig_config_size; i++){
		fprintf(stdout, "Trigger Config [%d]: %x\n", i, le32_to_cpu(hct_get_config_out->trig_config[i]));
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_HCT_READ_BUFFER CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_READ_BUFFER_OPCODE 50693
#define CXL_MEM_COMMAND_ID_HCT_READ_BUFFER_PAYLOAD_IN_SIZE 2
#define CXL_MEM_COMMAND_ID_HCT_READ_BUFFER_PAYLOAD_OUT_SIZE 1024

struct cxl_mbox_hct_read_buffer_in {
	u8 hct_inst;
	u8 num_entries_to_read;
}  __attribute__((packed));

struct cxl_mbox_hct_read_buffer_out {
	u8 buf_end;
	u8 num_buf_entries;
	__le16 rsvd;
	__le32 buf_entry[1024];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_hct_read_buffer(struct cxl_memdev *memdev,
	u8 hct_inst, u8 num_entries_to_read)
{
	u8 *buf_out;
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_hct_read_buffer_in *hct_read_buffer_in;
	struct cxl_mbox_hct_read_buffer_out *hct_read_buffer_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_READ_BUFFER_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_HCT_READ_BUFFER_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	hct_read_buffer_in = (void *) cmd->send_cmd->in.payload;

	hct_read_buffer_in->hct_inst = hct_inst;
	hct_read_buffer_in->num_entries_to_read = num_entries_to_read;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_READ_BUFFER) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_READ_BUFFER);
		return -EINVAL;
	}

	hct_read_buffer_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "========================== read hif/cxl trace buffer ===========================\n");
	fprintf(stdout, "Buffer End Reached: %x\n", hct_read_buffer_out->buf_end);
	fprintf(stdout, "Number of buffer entries: %x\n", hct_read_buffer_out->num_buf_entries);

	buf_out = (u8*) cmd->send_cmd->out.payload;
	fprintf(stdout, "Buffer Entries:\n");
	for(int i=4; i<cmd->send_cmd->out.size; i++){
		fprintf(stdout, "%02x ", buf_out[i]);
	}
	fprintf(stdout, "\n");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_HCT_SET_CONFIG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_HCT_SET_CONFIG_OPCODE 50690
#define CXL_MEM_COMMAND_ID_HCT_SET_CONFIG_PAYLOAD_IN_SIZE 136
#define HCT_SET_CONFIG_FIXED_PAYLOAD_IN_SIZE 8

struct cxl_mbox_hct_set_config_in {
	u8 hct_inst;
	u8 config_flags;
	u8 rsvd;
	u8 rsvd2;
	u8 post_trig_depth;
	u8 ignore_valid;
	u8 rsvd3;
	u8 rsvd4;
	u8 *trig_config[128];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_hct_set_config(struct cxl_memdev *memdev,
	u8 hct_inst, u8 config_flags, u8 post_trig_depth, u8 ignore_valid, int size, u8 *trig_config_buffer)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_hct_set_config_in *hct_set_config_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_HCT_SET_CONFIG_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = HCT_SET_CONFIG_FIXED_PAYLOAD_IN_SIZE + size;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	hct_set_config_in = (void *) cmd->send_cmd->in.payload;

	hct_set_config_in->hct_inst = hct_inst;
	hct_set_config_in->config_flags = config_flags;
	hct_set_config_in->post_trig_depth = post_trig_depth;
	hct_set_config_in->ignore_valid = ignore_valid;
	memcpy(hct_set_config_in->trig_config, trig_config_buffer, size);

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_HCT_SET_CONFIG) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_HCT_SET_CONFIG);
		return -EINVAL;
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG_OPCODE 51201
#define CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG_PAYLOAD_IN_SIZE 40

struct cxl_mbox_osa_os_patt_trig_cfg_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
	__le16 lane_mask;
	u8 lane_dir_mask;
	u8 rate_mask;
	__le32 patt_val[4];
	__le32 patt_mask[4];
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_osa_os_patt_trig_cfg(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u16 lane_mask, u8 lane_dir_mask, u8 rate_mask, u32 *patt_val,
	u32 *patt_mask)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_os_patt_trig_cfg_in *osa_os_patt_trig_cfg_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_os_patt_trig_cfg_in = (void *) cmd->send_cmd->in.payload;

	osa_os_patt_trig_cfg_in->cxl_mem_id = cxl_mem_id;
	osa_os_patt_trig_cfg_in->lane_mask = cpu_to_le16(lane_mask);
	osa_os_patt_trig_cfg_in->lane_dir_mask = lane_dir_mask;
	osa_os_patt_trig_cfg_in->rate_mask = rate_mask;
	for(int i = 0; i < 4; i++) {
		osa_os_patt_trig_cfg_in->patt_val[i] = cpu_to_le32(patt_val[i]);
	}

	for(int i = 0; i < 4; i++) {
		osa_os_patt_trig_cfg_in->patt_mask[i] = cpu_to_le32(patt_mask[i]);
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_OS_PATT_TRIG_CFG);
		return -EINVAL;
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG_OPCODE 51202
#define CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG_PAYLOAD_IN_SIZE 8

struct cxl_mbox_osa_misc_trig_cfg_in {
	u8 rsvd;
	u8 cxl_mem_id;
	__le16 rsvd2;
	u8 trig_en_mask;
	u8 rsvd5[3];
}  __attribute__((packed));


CXL_EXPORT int cxl_memdev_osa_misc_trig_cfg(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 trig_en_mask)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_misc_trig_cfg_in *osa_misc_trig_cfg_in;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_misc_trig_cfg_in = (void *) cmd->send_cmd->in.payload;

	osa_misc_trig_cfg_in->cxl_mem_id = cxl_mem_id;
	osa_misc_trig_cfg_in->trig_en_mask = trig_en_mask;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_MISC_TRIG_CFG);
		return -EINVAL;
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}


#define CXL_MEM_COMMAND_ID_OSA_DATA_READ CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_OSA_DATA_READ_OPCODE 51207
#define CXL_MEM_COMMAND_ID_OSA_DATA_READ_PAYLOAD_IN_SIZE 8
#define CXL_MEM_COMMAND_ID_OSA_DATA_READ_PAYLOAD_OUT_SIZE 140

struct cxl_mbox_osa_data_read_in {
	u8 rsvd;
	u8 cxl_mem_id;
	u8 lane_id;
	u8 lane_dir;
	__le16 start_entry;
	u8 num_entries;
	u8 rsvd7;
}  __attribute__((packed));

struct cxl_mbox_osa_data_read_out {
	u8 entries_read;
	u8 cxl_mem_id;
	u8 lane_id;
	u8 lane_dir;
	__le16 next_entry;
	__le16 entries_rem;
	u8 wrap;
	u8 rsvd[3];
	__le32 data[32];
}  __attribute__((packed));

CXL_EXPORT int cxl_memdev_osa_data_read(struct cxl_memdev *memdev,
	u8 cxl_mem_id, u8 lane_id, u8 lane_dir, u16 start_entry, u8 num_entries)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_osa_data_read_in *osa_data_read_in;
	struct cxl_mbox_osa_data_read_out *osa_data_read_out;
	int rc = 0;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_OSA_DATA_READ_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_OSA_DATA_READ_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	osa_data_read_in = (void *) cmd->send_cmd->in.payload;

	osa_data_read_in->cxl_mem_id = cxl_mem_id;
	osa_data_read_in->lane_id = lane_id;
	osa_data_read_in->lane_dir = lane_dir;
	osa_data_read_in->start_entry = cpu_to_le16(start_entry);
	osa_data_read_in->num_entries = num_entries;
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_OSA_DATA_READ) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_OSA_DATA_READ);
		return -EINVAL;
	}

	osa_data_read_out = (void *)cmd->send_cmd->out.payload;
	fprintf(stdout, "================================ osa data read =================================\n");
	fprintf(stdout, "total number of entries read: %x\n", osa_data_read_out->entries_read);
	fprintf(stdout, "CXL.MEM ID: %x\n", osa_data_read_out->cxl_mem_id);
	fprintf(stdout, "lane ID: %x\n", osa_data_read_out->lane_id);
	fprintf(stdout, "lane direction (see osa_lane_dir_enum): %x\n", osa_data_read_out->lane_dir);
	fprintf(stdout, "index of the next entry to read: %x\n", le16_to_cpu(osa_data_read_out->next_entry));
	fprintf(stdout, "number of entries remaining: %x\n", le16_to_cpu(osa_data_read_out->entries_rem));
	fprintf(stdout, "wrap indicator: %x\n", osa_data_read_out->wrap);
	fprintf(stdout, "Data: \n");
	for(int i=0; i<osa_data_read_out->entries_read;i++){
		fprintf(stdout,"Entry %d: %x\n", i, le32_to_cpu(osa_data_read_out->data[i]));
	}

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_DIMM_SPD_READ CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_DIMM_SPD_READ_OPCODE 50448
#define CXL_MEM_COMMAND_ID_DIMM_SPD_READ_PAYLOAD_IN_SIZE 12

struct cxl_mbox_dimm_spd_read_in {
	__le32 spd_id;
	__le32 offset;
	__le32 num_bytes;
}  __attribute__((packed));

#define SPD_MODULE_SERIAL_NUMBER_LEN (328 - 325 + 1) // 4 Bytes

void static
IntToString (u8 *String, u8 *Integer, u8 SizeInByte) {
  u8 Index;

  for (Index = 0; Index < SizeInByte; Index++) {
    *(String + Index * 2) = (*(Integer + Index) >> 4) & 0x0F;
    *(String + Index * 2 + 1) = *(Integer + Index) & 0x0F;
  }
  for (Index = 0; Index < (SizeInByte * 2); Index++) {
    if (*(String + Index) >= 0x0A) {
      *(String + Index) += 0x37;
    } else {
      *(String + Index) += 0x30;
    }
  }
  *(String + SizeInByte * 2) = 0x0;
}

static char * decode_ddr4_module_type(u8 *bytes) {
    char *type;
	switch (bytes[3]) {
    case 0x01: type = "RDIMM (Registered DIMM)"; break;
    case 0x02: type = "UDIMM (Unbuffered DIMM)"; break;
    case 0x03: type = "SODIMM (Small Outline Unbuffered DIMM)"; break;
    case 0x04: type = "LRDIMM (Load-Reduced DIMM)"; break;
    case 0x05: type = "Mini-RDIMM (Mini Registered DIMM)"; break;
    case 0x06: type = "Mini-UDIMM (Mini Unbuffered DIMM)"; break;
    case 0x08: type = "72b-SO-RDIMM (Small Outline Registered DIMM, 72-bit data bus)"; break;
    case 0x09: type = "72b-SO-UDIMM (Small Outline Unbuffered DIMM, 72-bit data bus)"; break;
    case 0x0c: type = "16b-SO-UDIMM (Small Outline Unbuffered DIMM, 16-bit data bus)"; break;
    case 0x0d: type = "32b-SO-UDIMM (Small Outline Unbuffered DIMM, 32-bit data bus)"; break;
    default: type = NULL;
    }
	return type;
}

static float ddr4_mtb_ftb_calc(unsigned char b1, signed char b2) {
    float mtb = 0.125;
    float ftb = 0.001;
    return b1 * mtb + b2 * ftb;
}

static int decode_ddr4_module_speed(u8 *bytes) {
    float ctime;
    float ddrclk;

    ctime = ddr4_mtb_ftb_calc(bytes[18], bytes[125]);
    ddrclk = 2 * (1000 / ctime);

    return ddrclk;
}

static int decode_ddr4_module_size(u8 *bytes) {
	double size;
	int sdrcap = 256 << (bytes[4] & 15);
    int buswidth = 8 << (bytes[13] & 7);
    int sdrwidth = 4 << (bytes[12] & 7);
    int signal_loading = bytes[6] & 3;
    int lranks_per_dimm = ((bytes[12] >> 3) & 7) + 1;

    if (signal_loading == 2) lranks_per_dimm *= ((bytes[6] >> 4) & 7) + 1;
	size = sdrcap / 8 * buswidth / sdrwidth * lranks_per_dimm;
	return (int) size/1024;
}

static char * decode_ddr4_manufacturer(u8 *bytes){
	char *manufacturer;
	u8 bank, index;
	u8 count = bytes[320];
	u8 code = bytes[321];

	if (code == 0x00 || code == 0xFF) {
		manufacturer = NULL;
		return manufacturer;

	}

	bank = count & 0x7f;
	index = code & 0x7f;
	if(bank >= VENDORS_BANKS) {
		manufacturer = NULL;
		return manufacturer;
	}
	manufacturer = (char *) vendors[bank][index-1];
	return manufacturer;
}

typedef enum {
    UNKNOWN           = 0,
    DIRECT_RAMBUS     = 1,
    RAMBUS            = 2,
    FPM_DRAM          = 3,
    EDO               = 4,
    PIPELINED_NIBBLE  = 5,
    SDR_SDRAM         = 6,
    MULTIPLEXED_ROM   = 7,
    DDR_SGRAM         = 8,
    DDR_SDRAM         = 9,
    DDR2_SDRAM        = 10,
    DDR3_SDRAM        = 11,
    DDR4_SDRAM        = 12,
    N_RAM_TYPES       = 13
} RamType;

static int decode_ram_type(u8 *bytes) {
	if (bytes[0] < 4) {
        switch (bytes[2]) {
        case 1: return DIRECT_RAMBUS;
        case 17: return RAMBUS;
        }
    } else {
        switch (bytes[2]) {
        case 1: return FPM_DRAM;
        case 2: return EDO;
        case 3: return PIPELINED_NIBBLE;
        case 4: return SDR_SDRAM;
        case 5: return MULTIPLEXED_ROM;
        case 6: return DDR_SGRAM;
        case 7: return DDR_SDRAM;
        case 8: return DDR2_SDRAM;
        case 11: return DDR3_SDRAM;
        case 12: return DDR4_SDRAM;
        }
    }

    return UNKNOWN;
}

static const char *ram_types[] = {"Unknown",   "Direct Rambus",    "Rambus",     "FPM DRAM",
                                  "EDO",       "Pipelined Nibble", "SDR SDRAM",  "Multiplexed ROM",
                                  "DDR SGRAM", "DDR SDRAM",        "DDR2", "DDR3",
                                  "DDR4"};

CXL_EXPORT int cxl_memdev_dimm_spd_read(struct cxl_memdev *memdev,
	u32 spd_id, u32 offset, u32 num_bytes)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	struct cxl_mbox_dimm_spd_read_in *dimm_spd_read_in;
	u8 *dimm_spd_read_out;
	u8 serial[9];
	int rc = 0;
	int buswidth;
	RamType ram_type;

	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_DIMM_SPD_READ_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	/* update payload size */
	cinfo->size_in = CXL_MEM_COMMAND_ID_DIMM_SPD_READ_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		 cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	dimm_spd_read_in = (void *) cmd->send_cmd->in.payload;

	dimm_spd_read_in->spd_id = cpu_to_le32(spd_id);
	dimm_spd_read_in->offset = cpu_to_le32(offset);
	dimm_spd_read_in->num_bytes = cpu_to_le32(num_bytes);
	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		 goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d\n",
				cxl_memdev_get_devname(memdev), rc);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_DIMM_SPD_READ) {
		 fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_DIMM_SPD_READ);
		return -EINVAL;
	}

	dimm_spd_read_out = (u8*)cmd->send_cmd->out.payload;
	ram_type = decode_ram_type(dimm_spd_read_out);

	fprintf(stdout, "=========================== DIMM SPD READ Data ============================\n");
	fprintf(stdout, "Output Payload:");
	for(int i=0; i<cmd->send_cmd->out.size; i++){
		if (i % 16 == 0)
		{
			fprintf(stdout, "\n%04x  %02x ", i+offset, dimm_spd_read_out[i]);
		}
		else
		{
			fprintf(stdout, "%02x ", dimm_spd_read_out[i]);
		}
	}
	fprintf(stdout, "\n\n");

	// Decoding SPD data for only DDR4 SDRAM.

	buswidth = 8 << (dimm_spd_read_out[13] & 7);

	fprintf(stdout, "\n\n====== DIMM SPD DECODE ============\n");
	fprintf(stdout, "Total Width: %s\n", "TBD");
	fprintf(stdout, "Data Width: %d bits\n", buswidth);
	fprintf(stdout, "Size: %d GB\n", decode_ddr4_module_size(dimm_spd_read_out));
	fprintf(stdout, "Form Factor: %s\n", "TBD");
	fprintf(stdout, "Set: %s\n", "TBD");
	fprintf(stdout, "Locator: %s\n", "DIMM_X");
	fprintf(stdout, "Bank Locator: %s\n", "_Node1_ChannelX_DimmX");
	fprintf(stdout, "Type: %s\n", ram_types[ram_type]);
	fprintf(stdout, "Type Detail: %s\n", decode_ddr4_module_type(dimm_spd_read_out));
	fprintf(stdout, "Speed: %d MT/s\n", decode_ddr4_module_speed(dimm_spd_read_out));
	fprintf(stdout, "Manufacturer: %s\n", decode_ddr4_manufacturer(dimm_spd_read_out));
	IntToString(serial, &dimm_spd_read_out[325], SPD_MODULE_SERIAL_NUMBER_LEN);
	fprintf(stdout, "Serial Number: %s\n", serial);
	fprintf(stdout, "Asset Tag: %s\n", "TBD");

out:
	cxl_cmd_unref(cmd);
	return rc;
	return 0;
}

#define CXL_MEM_COMMAND_ID_LOG_INFO CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_LOG_INFO_OPCODE 0X0401
#define DDR_TRAINING_STATUS_UUID "2f070da4-431c-4538-b41d-0c50c8f2e292"
#define CXL_MEM_COMMAND_ID_LOG_INFO_PAYLOAD_IN_SIZE 24

CXL_EXPORT int cxl_memdev_ddr_training_status(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mbox_get_log *get_log_input;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	u8 *ddr_training_status;
	int rc = 0;
	int offset = 0;


	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_LOG_INFO_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_LOG_INFO_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	get_log_input = (void *) cmd->send_cmd->in.payload;
	uuid_parse(DDR_TRAINING_STATUS_UUID, get_log_input->uuid);
	get_log_input->offset = 0;
	get_log_input->length = cmd->memdev->payload_max;


	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_LOG_INFO) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_LOG_INFO);
		return -EINVAL;
	}

	ddr_training_status = (u8*)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== DDR Training Status ============================\n");
	fprintf(stdout, "Output Payload:\n");
	for(int i=0; i<cmd->send_cmd->out.size; i++){
		if (i % 16 == 0)
		{
			fprintf(stdout, "\n%04x  %02x ", i+offset, ddr_training_status[i]);
		}
		else
		{
			fprintf(stdout, "%02x ", ddr_training_status[i]);
		}
	}
	fprintf(stdout, "\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
}

#define CXL_MEM_COMMAND_ID_DIMM_SLOT_INFO CXL_MEM_COMMAND_ID_RAW
#define CXL_MEM_COMMAND_ID_DIMM_SLOT_INFO_OPCODE 0xC520
#define CXL_MEM_COMMAND_ID_DIMM_SLOT_INFO_PAYLOAD_IN_SIZE 0

CXL_EXPORT int cxl_memdev_dimm_slot_info(struct cxl_memdev *memdev)
{
	struct cxl_cmd *cmd;
	struct cxl_mem_query_commands *query;
	struct cxl_command_info *cinfo;
	u8 *dimm_slot_info;
	int rc = 0;
	int offset = 0;


	cmd = cxl_cmd_new_raw(memdev, CXL_MEM_COMMAND_ID_DIMM_SLOT_INFO_OPCODE);
	if (!cmd) {
		fprintf(stderr, "%s: cxl_cmd_new_raw returned Null output\n",
				cxl_memdev_get_devname(memdev));
		return -ENOMEM;
	}

	query = cmd->query_cmd;
	cinfo = &query->commands[cmd->query_idx];

	cinfo->size_in = CXL_MEM_COMMAND_ID_LOG_INFO_PAYLOAD_IN_SIZE;
	if (cinfo->size_in > 0) {
		cmd->input_payload = calloc(1, cinfo->size_in);
		if (!cmd->input_payload)
			return -ENOMEM;
		cmd->send_cmd->in.payload = (u64)cmd->input_payload;
		cmd->send_cmd->in.size = cinfo->size_in;
	}

	rc = cxl_cmd_submit(cmd);
	if (rc < 0) {
		fprintf(stderr, "%s: cmd submission failed: %d (%s)\n",
				cxl_memdev_get_devname(memdev), rc, strerror(-rc));
		goto out;
	}

	rc = cxl_cmd_get_mbox_status(cmd);
	if (rc != 0) {
		fprintf(stderr, "%s: firmware status: %d:\n%s\n",
				cxl_memdev_get_devname(memdev), rc, DEVICE_ERRORS[rc]);
		rc = -ENXIO;
		goto out;
	}

	if (cmd->send_cmd->id != CXL_MEM_COMMAND_ID_DIMM_SLOT_INFO) {
		fprintf(stderr, "%s: invalid command id 0x%x (expecting 0x%x)\n",
				cxl_memdev_get_devname(memdev), cmd->send_cmd->id, CXL_MEM_COMMAND_ID_DIMM_SLOT_INFO);
		return -EINVAL;
	}

	dimm_slot_info = (u8*)cmd->send_cmd->out.payload;
	fprintf(stdout, "=========================== DIMM SLOT INFO ============================\n");
	fprintf(stdout, "Output Payload:\n");
	for(int i=0; i<cmd->send_cmd->out.size; i++){
		if (i % 16 == 0)
		{
			fprintf(stdout, "\n%04x  %02x ", i+offset, dimm_slot_info[i]);
		}
		else
		{
			fprintf(stdout, "%02x ", dimm_slot_info[i]);
		}
	}
	fprintf(stdout, "\n");
out:
	cxl_cmd_unref(cmd);
	return rc;
}
