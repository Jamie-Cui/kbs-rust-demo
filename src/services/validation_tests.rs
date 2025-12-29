// Copyright (c) 2025 Jamie Cui
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


use super::*;

#[test]
fn test_is_policy_id_matched() {
    let token_ids = vec![
        PolicyClaim {
            id: uuid::Uuid::new_v4(),
            version: "1.0".to_string(),
        },
        PolicyClaim {
            id: uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            version: "1.0".to_string(),
        },
    ];

    let policy_ids = vec![
        uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
        uuid::Uuid::new_v4(),
    ];

    assert!(is_policy_id_matched(&token_ids, &policy_ids));
}
