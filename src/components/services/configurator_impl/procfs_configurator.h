/*
 * procfs_configurator.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License Version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not,
 * write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */
#ifndef H_PROCFSCONFIGURATOR
#define H_PROCFSCONFIGURATOR

#include <linux/list.h>
#include <linux/sysctl.h>

#include "common/bool.h"
#include "common/locking.h"
#include "configurator/econfiguration_group.h"
#include "configurator/iconfigurator.h"

#ifndef TALPA_HAS_CTLTABLE
typedef struct ctl_table ctl_table;
#endif

typedef struct
{
    struct list_head            list;
    IConfigurable*              item;
    ctl_table                   *config;
    struct ctl_table_header     *exposedConfig;
} ConfiguredItem;

typedef struct tag_ProcfsConfigurator
{
    IConfigurator           i_IConfigurator;
    void                    (*delete)(struct tag_ProcfsConfigurator* object);
    bool                    mInitialized;
    talpa_mutex_t           mSemaphore;
    struct list_head        mConfig;
    int                     mElementId;
} ProcfsConfigurator;

/*
 * Object creation/destruction.
 */
ProcfsConfigurator* newProcfsConfigurator(void);

#endif

/*
 * End of procfs_configurator.h
 */


