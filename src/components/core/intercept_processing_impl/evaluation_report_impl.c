/*
 * evaluation_report_impl.c
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
#include <linux/kernel.h>

#include <linux/string.h>

#include "evaluation_report_impl.h"

#include "platform/alloc.h"
/*
 * Forward declare implementation methods.
 */
static void             get                         (void* self);
static void*            customData                  (const void* self, int id, int* size);
static void             setCustomData               (void* self, int id, void* data, int size);
static EInterceptAction recommendedAction           (const void* self);
static void             setRecommendedAction        (void* self, EInterceptAction action);
static int              consecutiveTimeouts         (const void* self);
static int              errorCode                   (const void* self);
static void             setErrorCode                (void* self, int errCode);
static void             deleteEvaluationReportImpl  (struct tag_EvaluationReportImpl* object);
static bool             hasBeenExternallyVetted     (const void* self);
static void             externallyVetted            (void* self);
/*
 * Template Object.
 */
static EvaluationReportImpl template_EvaluationReportImpl =
    {
        {
            get,
            customData,
            setCustomData,
            recommendedAction,
            setRecommendedAction,
            consecutiveTimeouts,
            errorCode,
            setErrorCode,
            hasBeenExternallyVetted,
            externallyVetted,
            NULL,
            (void (*)(void*))deleteEvaluationReportImpl
        },
        deleteEvaluationReportImpl,
        ATOMIC_INIT(1),
        {},
        EIA_Next,
        0,
        0,
        false
    };
#define this    ((EvaluationReportImpl*)self)


/*
 * Object creation/destruction.
 */
EvaluationReportImpl* newEvaluationReportImpl(int current_timeouts)
{
    EvaluationReportImpl* object;


    object = talpa_alloc(sizeof(template_EvaluationReportImpl));
    if ( likely(object != NULL) )
    {
        memcpy(object, &template_EvaluationReportImpl, sizeof(template_EvaluationReportImpl));
        object->i_IEvaluationReport.object = object;

        TALPA_INIT_LIST_HEAD(&object->mCustom);
        object->mTimeouts = current_timeouts;
    }

    return object;
}

static void deleteEvaluationReportImpl(struct tag_EvaluationReportImpl* object)
{
    if ( atomic_dec_and_test(&object->mRefCnt) )
    {
        talpa_list_head*   posptr;
        talpa_list_head*   nptr;


        /*
        * We are responsible for the custom data.....so we do need to destroy them.
        */
        talpa_list_for_each_safe(posptr, nptr, &object->mCustom)
        {
            talpa_list_del(posptr);
            talpa_free(talpa_list_entry(posptr, EvaluationStorage, list)->data);
            talpa_free(talpa_list_entry(posptr, EvaluationStorage, list));
        }
        talpa_free(object);
    }
    return;
}

/*
 * IEvaluationReport.
 */
static void get(void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static void* customData(const void* self, int id, int* size)
{
    EvaluationStorage*   posptr;


    talpa_list_for_each_entry(posptr, &this->mCustom, list)
    {
        if (posptr->id == id)
        {
            *size = posptr->size;
            return posptr->data;
        }
    }
    *size = 0;
    return NULL;
}

static void setCustomData(void* self, int id, void* data, int size)
{
    EvaluationStorage*   posptr;
    EvaluationStorage*   storage = NULL;


    talpa_list_for_each_entry(posptr, &this->mCustom, list)
    {
        if (posptr->id == id)
        {
            storage = posptr;
            break;
        }
    }

    if ( storage )
    {
        if ( storage->size != size )
        {
            talpa_free(storage->data);
            storage->data = NULL;
            storage->size = 0;
        }
    }
    else
    {
        storage = talpa_zalloc(sizeof(*storage));
        TALPA_INIT_LIST_HEAD(&storage->list);
        storage->id = id;
        talpa_list_add_tail(&storage->list, &(this->mCustom));
    }

    if ( !storage->data )
    {
        storage->data = talpa_alloc(size);
    }

    if ( storage->data )
    {
        storage->size = size;
        memcpy(storage->data, data, size);
    }

    return;
}

static EInterceptAction recommendedAction(const void* self)
{
    return this->mRecommendedAction;
}

static void setRecommendedAction(void* self, EInterceptAction action)
{
    this->mRecommendedAction = action;
    return;
}

static int consecutiveTimeouts(const void* self)
{
    return this->mTimeouts;
}

static int errorCode(const void* self)
{
    return this->mError;
}

static void setErrorCode(void* self, int errCode)
{
    this->mError = errCode;
    return;
}

static bool hasBeenExternallyVetted(const void* self)
{
    return this->mExternallyVetted;
}

static void externallyVetted(void* self)
{
    this->mExternallyVetted = true;
    return;
}
/*
 * End of evaluation_report_impl.c
 */

