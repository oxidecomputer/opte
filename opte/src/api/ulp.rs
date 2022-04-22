// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

/// Port 0 is reserved by the sockets layer. It is used by clients to
/// indicate they want the operating system to choose a port on their
/// behalf.
pub const DYNAMIC_PORT: u16 = 0;
