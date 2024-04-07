# SPDX-License-Identifier: BSD-3-Clause

if not is_linux
        build = false
        reason = 'only supported on linux'
endif

#subdir('base')
#objs = [base_objs]

sources = files('base/tsrn10_api.c',
                'tsrn10_ethdev.c',
                'tsrn10_rxtx.c',
                'tsrn10_mbx.c',
                'tsrn10_mbx_fw.c',
                'tsrn10_flow.c',
                'tsrn10_vf.c',
                'tsrn10_ptp.c',
                'tsrn10_pcs.c',
                'tsrn10_phy.c',
               )

deps += ['hash', 'security']

if arch_subdir == 'x86'
sources += files('tsrn10_rxtx_vec_sse.c')
elif arch_subdir == 'arm'
sources += files('tsrn10_rxtx_vec_neon.c')
endif

includes += include_directories('base')
