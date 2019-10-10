/*
 * device_driver_process_exclusion.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2019 Sophos Limited, Oxford, England.
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
#ifndef H_IDEVICEDRIVERTHREADEXCLUSION
#define H_IDEVICEDRIVERTHREADEXCLUSION


#include "common/locking.h"
#include "common/list.h"
#include "system_interfaces/idevice_file.h"
#include "configurator/iconfigurable.h"
#include "configurator/iconfigurator.h"
#include "process_excluder/iprocess_excluder.h"


/*
 * Exported kernel interface
 */
int talpa_pedevice_attach(void);
int talpa_pedevice_detach(void);

/*
 * Configuration structures
 */

#define DDPE_CFGDATASIZE      (16)
#define DDPE_CFGLOCATIONSIZE  (128)

typedef struct {
    char    name[DDPE_CFGDATASIZE];
    char    value[DDPE_CFGDATASIZE];
} DDPEConfigData;

typedef struct {
    char    name[DDPE_CFGDATASIZE];
    char    value[DDPE_CFGLOCATIONSIZE];
} DDPELocationConfigData;

struct DDPEOpenContext
{
    talpa_list_head     head;
    pid_t               pid;
    pid_t               tid;
    void*               files;
    bool                modified;
    bool                state;
    ProcessExcluded*    excluded;
};

typedef struct tag_DeviceDriverProcessExclusion
{
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_DeviceDriverProcessExclusion* object);
    bool                        (*attach)(void* self);
    bool                        (*detach)(void* self);
    struct rw_semaphore         mSem;
    IProcessExcluder*           mProcExcl;
    talpa_list_head             mContextList;
    IConfigurator*              mConfigurator;
    bool                        mAttached;
    PODConfigurationElement     mConfig[3];
    DDPEConfigData              mDeviceConfigData;
    DDPELocationConfigData      mLocationConfigData;
} DeviceDriverProcessExclusion;


/*
 * Object Creators.
 */
DeviceDriverProcessExclusion* newDeviceDriverProcessExclusion(void);

#endif

/*
 * End of device_driver_process_exclusion.h
 */

