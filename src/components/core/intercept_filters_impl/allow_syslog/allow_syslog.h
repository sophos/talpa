/*
 * allow_syslog.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2017 Sophos Limited, Oxford, England.
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
#ifndef H_ALLOWSYSLOGFILTER
#define H_ALLOWSYSLOGFILTER


#include "common/locking.h"
#include "intercept_filters/iintercept_filter.h"
#include "configurator/iconfigurable.h"

#define ALLOWSYSLOGFILTER_CFGDATASIZE      (16)

typedef struct {
    char    name[ALLOWSYSLOGFILTER_CFGDATASIZE];
    char    value[ALLOWSYSLOGFILTER_CFGDATASIZE];
} AllowSyslogFilterConfigData;

typedef struct tag_AllowSyslogFilter
{
    IInterceptFilter            i_IInterceptFilter;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_AllowSyslogFilter* object);
    talpa_mutex_t               mConfigSerialize;
    bool                        mEnabled;
    char                        mName[64];
    PODConfigurationElement     mConfig[2];
    AllowSyslogFilterConfigData  mConfigData;
} AllowSyslogFilter;

/*
 * Object Creators.
 */
AllowSyslogFilter* newAllowSyslogFilter(const char *name);


#endif

/*
 * End of allow_syslog.h
 */

