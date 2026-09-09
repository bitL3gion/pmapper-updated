"""Utility code for running I/O-bound AWS API calls concurrently.

Botocore clients are documented as safe to share and call concurrently from multiple threads (unlike boto3
Resource objects), which makes a simple bounded thread pool an easy, safe way to speed up the many
per-principal/per-resource API calls PMapper makes while gathering data (e.g. one `list_access_keys` call per
IAM user). Threads help here specifically because these calls are I/O-bound: the GIL is released while
waiting on the network, so a thread pool gives a near-linear speedup up to whatever concurrency the AWS API
throttling limits allow.
"""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import concurrent.futures
from typing import Callable, Iterable, List, TypeVar

# Default degree of concurrency for gathering API calls. Kept modest by default to stay well under
# IAM/other services' steady-state throttling limits; callers can raise it (e.g. via `pmapper graph create
# --max-threads`) for large accounts where more concurrency is safe/desired.
DEFAULT_MAX_WORKERS = 10

T = TypeVar('T')
R = TypeVar('R')


def thread_map(fn: Callable[[T], R], items: Iterable[T], max_workers: int = DEFAULT_MAX_WORKERS) -> List[R]:
    """Applies `fn` to each item in `items` using a bounded pool of threads, and returns the list of results.

    Result order is not guaranteed to match input order. If `fn` raises for any item, that exception
    propagates out of this call (after all submitted work has completed), matching the fail-fast behavior of
    a plain `for` loop calling `fn` directly.

    Falls back to a plain sequential loop when there's 0 or 1 items, or `max_workers` is 1, to avoid the
    overhead of spinning up a thread pool for trivial input.
    """
    items = list(items)
    if len(items) <= 1 or max_workers <= 1:
        return [fn(item) for item in items]

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as executor:
        futures = [executor.submit(fn, item) for item in items]
        return [future.result() for future in concurrent.futures.as_completed(futures)]
