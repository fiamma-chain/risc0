// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::test_harness::{test_witgen, test_zkr, witness_test_data, bigint_tests, bigint_short_tests};
use crate::{BigIntClaim, BigIntContext, BIGINT_PO2};
use anyhow::Result;
use num_bigint::BigUint;
use risc0_zkp::core::hash::sha;
use risc0_zkp::field::{
    baby_bear::{BabyBearElem, BabyBearExtElem},
    Elem, ExtElem,
};
use test_log::test;




// fn ec_aff_sub_test_golden_values() -> Vec<BigUint> {
//     // TODO: These specific values yield an A - (-A), which should give a failure
//     // TODO: Add a test to ensure they do?
//     Vec::from([
//         from_hex("0b"), // prime:      11
//         from_hex("05"), // curve_a:     5
//         from_hex("01"), // curve_b:     1
//         from_hex("07"), // lhs_x:       7
//         from_hex("04"), // lhs_y:       4
//         from_hex("07"), // rhs_x:       7
//         from_hex("07"), // rhs_y:       7
//         from_hex("06"), // expected_x:  6
//         from_hex("04"), // expected_y:  4
//     ])
// }



// name(zkr, in_values, public_witness, private_witness, constant_witness, golden_z)
bigint_tests! {
    ec_aff_add_test_8(
        ec_aff_add_test_8,
        [
            "06",   // lhs_x:       6
            "04",   // lhs_y:       4
            "07",   // rhs_x:       7
            "07",   // rhs_y:       7
            "07",   // expected_x:  7
            "04",   // expected_y:  4
        ],
        ["06", "04", "07", "07", "07", "04"],
        [
            "01", "010000", "43434343", "5f5f5f5f", "03", "030000", "43434343", "5f5f5f5f", "010000", "07",
            "010000", "04", "43434343", "5f5f5f5f", "43434343", "5f5f5f5f", "22", "22",
            // "22", "01", "03", "c3c3", "1f1f", "22", "01", "03", "c3c3", "1f1f", "01", "01", "c3c3", "1f1f", "01", "c3c3", "1f1f", "01", "000000", "01", "43434343",
            // "5f5f5f5f", "22", "000000", "03", "43434343", "5f5f5f5f", "010000", "07", "43434343",
            // "5f5f5f5f", "00", "08", "c3c3", "1f1f", "000000", "09", "43434343", "5f5f5f5f", "01", "07",
            // "c3c3", "1f1f", "010000", "0a", "43434343", "5f5f5f5f", "00", "04", "c3c3", "1f1f", "22",
            // "22",
        ],
        ["01", "0b"],
        [1146486859, 83217818, 38193709, 1815305313]
    ),
    ec_aff_add_test_8_reverse(  // TODO: Regularize or remove (this is `ec_aff_add_test_8` with LHS & RHS swapped)
        ec_aff_add_test_8,
        [
            "07",   // lhs_x:       7
            "07",   // lhs_y:       7
            "06",   // rhs_x:       6
            "04",   // rhs_y:       4
            "07",   // expected_x:  7
            "04",   // expected_y:  4
        ],
        ["07", "07", "06", "04", "07", "04"],
        [
            "0a", "090000", "43434343",
            "5f5f5f5f", "03", "030000", "43434343", "5f5f5f5f", "010000", "07", "010000",
            "04", "43434343", "5f5f5f5f", "43434343", "5f5f5f5f", "22", "22",
        ],
        ["01", "0b"],
        [1523456991, 1263987236, 1555071918, 1666051369]
    ),
    ec_aff_sub_test_8(
        ec_aff_sub_test_8,
        [
            "07", // lhs_x:       7
            "04", // lhs_y:       4
            "06", // rhs_x:       6
            "04", // rhs_y:       4
            "07", // expected_x:  7
            "07", // expected_y:  7
        ],
        ["07", "04", "06", "04", "07", "07"],
        [
            "0a", "090000", "43434343",
            "5f5f5f5f", "08", "070000", "43434343", "5f5f5f5f", "060000", "07", "0c0000",
            "07", "43434343", "5f5f5f5f",
            "43434343", "5f5f5f5f", "22",
            "22"
        ],
        ["01", "0b"],
        [238608548, 1477743974, 1530619081, 1621476502]
    ),
    ec_aff_doub_test_8(
        ec_aff_doub_test_8,
        [
            "06",   // lhs_x:       6
            "04",   // lhs_y:       4
            "00",   // expected_x:  0
            "01",   // expected_y:  1
        ],
        ["06", "04", "00", "01"],
        [
            "030000", "03", "43434343", "5f5f5f5f", "010000", "03", "43434343", "5f5f5f5f", "00", "08",
            "c3c3", "1f1f", "07", "050000", "01", "43434343", "5f5f5f5f", "22", "010000", "0a",
            "43434343", "5f5f5f5f", "050000", "05", "43434343", "5f5f5f5f", "00", "0a", "c3c3", "1f1f",
            "090000", "01", "43434343", "5f5f5f5f", "01", "00", "c3c3", "1f1f", "000000", "00",
            "43434343", "5f5f5f5f", "01", "01", "c3c3", "1f1f", "22", "22", "2222",
        ],
        ["05", "03", "01", "0b"],
        [1458665736, 281860481, 1388334501, 189857820]
    ),
    ec_aff_neg_test_8(
        ec_aff_neg_test_8,
        [
            "06", // inp_x:       6
            "04", // inp_y:       4
            "06", // expected_x:  7
            "07", // expected_y:  4
        ],
        ["06", "04","06", "07"],
        ["22", "22"],
        ["0b"],
        [1044718500, 1494589160, 1951071568, 947405500]
    ),
    ec_pts_eq_test_8(
        ec_pts_eq_test_8,
        [
            "06", // lhs_x:       6
            "04", // lhs_y:       4
            "06", // rhs_x:       6
            "04", // rhs_y:       4
        ],
        ["06", "04", "06", "04"],
        ["22", "22"],
        [],
        [622647450, 1812942703, 750340746, 582495994]
    ),
}

// name(zkr, in_values, golden_z)
bigint_short_tests! {
    ec_aff_mul1_test_8(
        ec_aff_mul_test_8,
        [
            "ac",   // inp_x:      172
            "3c",   // inp_y:       60
            "01",   // scale:        1
            "07",   // arb_x:        7
            "02",   // arb_y:        2
            "ac",   // expected_x: 172
            "3c",   // expected_y:  60
        ],
        // ["ac", "3c", "01", "07", "02", "ac", "3c"],
        // [
        //     "22", "22", "22", "22", "22", "22", "22", "000000", "31", "43434343", "5f5f5f5f", "b50000",
        //     "00", "43434343", "5f5f5f5f", "22",
        //     "01", "00", "c3c3", "1f1f", "c3c3", "1f1f", "72", "dd0000", "43434343", "5f5f5f5f", "2f",
        //     "5a0000", "43434343", "5f5f5f5f", "0d0000", "a60000", "91", "43434343", "5f5f5f5f", "43434343", "5f5f5f5f",
        //     "000000", "3d", "43434343", "5f5f5f5f", "000000", "91", "43434343", "5f5f5f5f", "5b", "2b", "390300",
        //     "2a434343", "5d5f5f5f",
        //      "0a", "c3c3", "1f1f", "0a", "090000", "01", "43434343",
        //     "5f5f5f5f", "22", "020000", "08", "43434343", "5f5f5f5f", "050000", "01", "43434343",
        //     "5f5f5f5f", "01", "03", "c3c3", "1f1f", "050000", "09", "43434343", "5f5f5f5f", "01", "07",
        //     "c3c3", "1f1f", "050000", "01", "43434343", "5f5f5f5f", "01", "07", "c3c3", "1f1f", "22",
        //     "22",
        // ],
        // ["01"],
        [346372436, 1604795053, 31129203, 246390035]
    ),
    ec_aff_mul113_test_8(
        ec_aff_mul_test_8,
        [
            "9d",   // inp_x:      157
            "22",   // inp_y:       34
            "71",   // scale:      113
            "07",   // arb_x:        7
            "02",   // arb_y:        2
            "74",   // expected_x: 116
            "a7",   // expected_y: 167
        ],
        // ["9d", "22", "71", "07", "02", "74", "a7"],
        // [
        //     "01", "03", "c3c3", "1f1f", "00", "0a", "c3c3", "1f1f", "0a", "090000", "01", "43434343",
        //     "5f5f5f5f", "22", "020000", "08", "43434343", "5f5f5f5f", "050000", "01", "43434343",
        //     "5f5f5f5f", "01", "03", "c3c3", "1f1f", "050000", "09", "43434343", "5f5f5f5f", "01", "07",
        //     "c3c3", "1f1f", "050000", "01", "43434343", "5f5f5f5f", "01", "07", "c3c3", "1f1f", "22",
        //     "22",
        // ],
        // ["01"],
        [346372436, 1604795053, 31129203, 246390035]
    ),
    ec_aff_mul2_test_32(
        ec_aff_mul_test_32,
        [
            "37",   // inp_x:       55
            "90",   // inp_y:      144
            "02",   // scale:        2
            "07",   // arb_x:        7
            "b1",   // arb_y:      177
            "97",   // expected_x: 151
            "ac",   // expected_y: 172
        ],
        // ["37000000", "90000000", "02000000", "07000000", "b1000000", "97000000", "ac000000"],
        // [
        //     "01", "03", "c3c3", "1f1f", "00", "0a", "c3c3", "1f1f", "0a", "090000", "01", "43434343",
        //     "5f5f5f5f", "22", "020000", "08", "43434343", "5f5f5f5f", "050000", "01", "43434343",
        //     "5f5f5f5f", "01", "03", "c3c3", "1f1f", "050000", "09", "43434343", "5f5f5f5f", "01", "07",
        //     "c3c3", "1f1f", "050000", "01", "43434343", "5f5f5f5f", "01", "07", "c3c3", "1f1f", "22",
        //     "22",
        // ],
        // ["01"],
        [346372436, 1604795053, 31129203, 246390035]
    ),
    // ec_aff_mul2_test_256(
    //     ec_aff_mul_test_256,
    //     [
    //         "06",   // inp_x:       6
    //         "04",   // inp_y:       4
    //         "02",   // scale:       2
    //         "08",   // arb_x:       8
    //         "05",   // arb_y:       5
    //         "000b", // order:      11
    //         "00",   // expected_x:  0
    //         "01",   // expected_y:  1
    //     ],
    //     ["06", "04", "02", "08", "05", "0b00", "00", "01"],  // TODO: Unconvinced these numbers are right
    //     [
    //         "01", "03", "c3c3", "1f1f", "00", "0a", "c3c3", "1f1f", "0a", "090000", "01", "43434343",
    //         "5f5f5f5f", "22", "020000", "08", "43434343", "5f5f5f5f", "050000", "01", "43434343",
    //         "5f5f5f5f", "01", "03", "c3c3", "1f1f", "050000", "09", "43434343", "5f5f5f5f", "01", "07",
    //         "c3c3", "1f1f", "050000", "01", "43434343", "5f5f5f5f", "01", "07", "c3c3", "1f1f", "22",
    //         "22",
    //     ],
    //     ["01"],
    //     [346372436, 1604795053, 31129203, 246390035]
    // ),
}