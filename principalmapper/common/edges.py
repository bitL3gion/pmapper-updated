"""Python module containing the basic Edge class, as well as any utility functions (currently none)."""


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

from typing import List, Optional

from principalmapper.util import arns


class Edge(object):
    """The Edge object: contains a source and destination Node object, as well as a string that explains how
    the source Node is able to access the destination Node.

    `permissions` is the list of specific IAM actions (e.g. `iam:PassRole`, `ec2:RunInstances`) that were
    identified as enabling this edge. `commands` is a list of example AWS CLI commands that demonstrate how the
    edge could be exploited, using the actual ARNs/names involved where they're known. Both are optional so that
    older callers/serialized data (without this information) continue to work.
    """

    def __init__(self, source, destination, reason: str, short_reason: str,
                permissions: Optional[List[str]] = None, commands: Optional[List[str]] = None):
        """Constructor"""
        if source is None:
            raise ValueError('Edges must have a source Node object')
        if destination is None:
            raise ValueError('Edges must have a destination Node object')
        if reason is None:
            raise ValueError('Edges must be constructed with a reason parameter (str)')
        if short_reason is None:
            raise ValueError('Edges must be constructed with a short_reason parameter (str)')

        self.source = source
        self.destination = destination
        self.reason = reason
        self.short_reason = short_reason
        self.permissions = permissions if permissions is not None else []
        self.commands = commands if commands is not None else []

    def describe_edge(self) -> str:
        """Returns a human-readable string explaining the edge"""
        return "{} {} {}".format(
            self.source.searchable_name(),
            self.reason,
            self.destination.searchable_name()
        )

    def detailed_description(self) -> str:
        """Returns a human-readable, multi-line string explaining the edge, including the specific IAM
        permissions involved and example command(s) that could be used to exploit it."""
        lines = [self.describe_edge()]
        if self.permissions:
            lines.append('Permissions involved: {}'.format(', '.join(self.permissions)))
        if self.commands:
            lines.append('Example command(s):')
            lines.extend('  {}'.format(command) for command in self.commands)
        return '\n'.join(lines)

    def to_dictionary(self) -> dict:
        """Returns a dictionary representation of this object for storage"""
        return {
            'source': self.source.arn,
            'destination': self.destination.arn,
            'reason': self.reason,
            'short_reason': self.short_reason,
            'permissions': self.permissions,
            'commands': self.commands
        }
