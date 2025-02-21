#include "config.h"
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>

#define BLE_HANDLE 0x001E

#define XBOX_BTN_PROFILE        0x000001
#define XBOX_BTN_VIEW           0x000400
#define XBOX_BTN_MENU           0x000800
#define XBOX_BTN_XBOX           0x001000
#define XBOX_BTN_JOY_LEFT       0x002000
#define XBOX_BTN_JOY_RIGHT      0x004000
#define XBOX_BTN_A              0x010000
#define XBOX_BTN_B              0x020000
#define XBOX_BTN_X              0x080000
#define XBOX_BTN_Y              0x100000
#define XBOX_BTN_BACK_LEFT      0x400000
#define XBOX_BTN_BACK_RIGHT     0x800000

static int proto_xbox;

static int hf_xbox_joy_left;
static int hf_xbox_joy_left_x;
static int hf_xbox_joy_left_y;

static int hf_xbox_joy_right;
static int hf_xbox_joy_right_x;
static int hf_xbox_joy_right_y;

static int hf_xbox_trg_left;
static int hf_xbox_trg_right;

static int hf_xbox_pad;

static int hf_xbox_btn;
static int hf_xbox_btn_back_left;
static int hf_xbox_btn_back_right;
static int hf_xbox_btn_profile;
static int hf_xbox_btn_view;
static int hf_xbox_btn_menu;
static int hf_xbox_btn_xbox;
static int hf_xbox_btn_a;
static int hf_xbox_btn_b;
static int hf_xbox_btn_x;
static int hf_xbox_btn_y;
static int hf_xbox_btn_joy_left;
static int hf_xbox_btn_joy_right;


static int ett_main;
static int ett_joyleft;
static int ett_joyright;

static dissector_handle_t xbox_handle;

static const value_string dpad_string[] = {
    { 0, "" },
    { 1, "Top" },
    { 2, "Top-Right" },
    { 3, "Right" },
    { 4, "Bottom-Right" },
    { 5, "Bottom" },
    { 6, "Bottom-Left" },
    { 7, "Left" },
    { 8, "Top-Left" }
};

static int dissect_xbox(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static int* const btn_bits[] = {
        &hf_xbox_btn_back_left,
        &hf_xbox_btn_back_right,
        &hf_xbox_btn_profile,
        &hf_xbox_btn_view,
        &hf_xbox_btn_menu,
        &hf_xbox_btn_xbox,
        &hf_xbox_btn_a,
        &hf_xbox_btn_b,
        &hf_xbox_btn_x,
        &hf_xbox_btn_y,
        &hf_xbox_btn_joy_left,
        &hf_xbox_btn_joy_right,
        NULL
    };

    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XBOX");
    col_set_str(pinfo->cinfo, COL_INFO, "XBOX action");

    proto_item *main_item = proto_tree_add_item(tree, proto_xbox, tvb, 0, -1, ENC_NA);
    proto_tree *main_tree = proto_item_add_subtree(main_item, ett_main);

    // Joystick Left
    proto_item *joyleft_item = proto_tree_add_item(main_tree, hf_xbox_joy_left, tvb, 0, 4, ENC_NA);
    proto_tree *joyleft_tree = proto_item_add_subtree(joyleft_item, ett_joyleft);
    proto_tree_add_item(joyleft_tree, hf_xbox_joy_left_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(joyleft_tree, hf_xbox_joy_left_y, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // Joystick Right
    proto_item *joyright_item = proto_tree_add_item(main_tree, hf_xbox_joy_right, tvb, offset, 4, ENC_NA);
    proto_tree *joyright_tree = proto_item_add_subtree(joyright_item, ett_joyright);
    proto_tree_add_item(joyright_tree, hf_xbox_joy_right_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(joyright_tree, hf_xbox_joy_right_y, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // Trigger Left
    proto_tree_add_item(main_tree, hf_xbox_trg_left, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // Trigger Right
    proto_tree_add_item(main_tree, hf_xbox_trg_right, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // Directional Pad
    proto_tree_add_item(main_tree, hf_xbox_pad, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    // TODO

    // Back Button
   proto_tree_add_bitmask(main_tree, tvb, offset, hf_xbox_btn, ett_main, btn_bits, ENC_BIG_ENDIAN);
    offset += 3;


    return tvb_captured_length(tvb);
}

void proto_register_xbox(void)
{
     static hf_register_info hf[] = {
        { &hf_xbox_joy_left,
          { "Joystic Left", "xbox.joyleft",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_joy_left_x,
            { "X axis", "xbox.joyleft.x",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_joy_left_y,
            { "Y axis", "xbox.joyleft.y",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_xbox_joy_right,
          { "Joystic Right", "xbox.joyright",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_joy_right_x,
            { "X axis", "xbox.joyright.x",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_joy_right_y,
            { "Y axis", "xbox.joyright.y",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_trg_left,
            { "Trigger Left", "xbox.trgright",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_trg_right,
            { "Trigger Right", "xbox.trgleft",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_pad,
            { "Directional Pad", "xbox.dpad",
            FT_UINT8, BASE_HEX,
            VALS(dpad_string), 0x0,
            NULL, HFILL }
        },
        { &hf_xbox_btn,
            {"Button", "xbox.btn",
            FT_UINT24, BASE_HEX, 
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_xbox_btn_back_left,
            {"Back Left", "xbox.btn.bck.left",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_BACK_LEFT,
            NULL, HFILL}
        },
        { &hf_xbox_btn_back_right,
            {"Back Right", "xbox.btn.bck.right",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_BACK_RIGHT,
            NULL, HFILL}
        },
        { &hf_xbox_btn_profile,
            {"Profile", "xbox.btn.profile",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_PROFILE,
            NULL, HFILL}
        },
        { &hf_xbox_btn_view,
            {"View", "xbox.btn.view",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_VIEW,
            NULL, HFILL}
        },
        { &hf_xbox_btn_menu,
            {"Menu", "xbox.btn.menu",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_MENU,
            NULL, HFILL}
        },
        { &hf_xbox_btn_xbox,
            {"Xbox", "xbox.btn.xbox",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_XBOX,
            NULL, HFILL}
        },
        { &hf_xbox_btn_a,
            {"A", "xbox.btn.a",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_A,
            NULL, HFILL}
        },
        { &hf_xbox_btn_b,
            {"B", "xbox.btn.b",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_B,
            NULL, HFILL}
        },
        { &hf_xbox_btn_x,
            {"X", "xbox.btn.x",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_X,
            NULL, HFILL}
        },
        { &hf_xbox_btn_y,
            {"Y", "xbox.btn.y",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_Y,
            NULL, HFILL}
        },
        { &hf_xbox_btn_joy_left,
            {"Joystic Left", "xbox.btn.joy.left",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_JOY_LEFT,
            NULL, HFILL}
        },
        { &hf_xbox_btn_joy_right,
            {"Joystick Right", "xbox.btn.joy.right",
            FT_BOOLEAN, 24, 
            NULL, XBOX_BTN_JOY_RIGHT,
            NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_main,
        &ett_joyleft,
        &ett_joyright
    };

    proto_xbox = proto_register_protocol (
        "Xbox Controller Protocol", /* name        */
        "Xbox",          /* short_name  */
        "xbox"           /* filter_name */
        );

    proto_register_field_array(proto_xbox, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    //subdissector_table = register_decode_as_next_proto(proto_xbox, "xbox.dissector", "xbox protocol dissector", NULL);
    
}

void proto_reg_handoff_xbox(void)
{
    xbox_handle = register_dissector("xbox", dissect_xbox, proto_xbox);
    dissector_add_uint("btatt.handle", BLE_HANDLE,
                            xbox_handle);
}