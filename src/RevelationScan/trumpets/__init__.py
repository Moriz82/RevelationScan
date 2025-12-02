"""Trumpet modules."""
from __future__ import annotations

from typing import List, Type

from .accounts import AccountsTrumpet
from .capabilities import CapabilitiesTrumpet
from .cron import CronTrumpet
from .docker import DockerTrumpet
from .kernel_hardening import KernelHardeningTrumpet
from .listening_ports import ListeningPortsTrumpet
from .nfs import NFSTrumpet
from .packages import PackageMetadataTrumpet
from .path_hygiene import PathHygieneTrumpet
from .sensitive_files import SensitiveFilesTrumpet
from .service_versions import ServiceVersionTrumpet
from .setuid import SetuidTrumpet
from .ssh import SSHConfigTrumpet
from .sudoers import SudoersTrumpet
from .systemd import SystemdExecTrumpet
from .world_writable import WorldWritableTrumpet
from .writable_devices import WritableDevicesTrumpet


def builtin_trumpets() -> List[Type]:
    return [
        WorldWritableTrumpet,
        PathHygieneTrumpet,
        SensitiveFilesTrumpet,
        SudoersTrumpet,
        SetuidTrumpet,
        CronTrumpet,
        SystemdExecTrumpet,
        SSHConfigTrumpet,
        NFSTrumpet,
        DockerTrumpet,
        ListeningPortsTrumpet,
        CapabilitiesTrumpet,
        WritableDevicesTrumpet,
        AccountsTrumpet,
        KernelHardeningTrumpet,
        ServiceVersionTrumpet,
        PackageMetadataTrumpet,
    ]
