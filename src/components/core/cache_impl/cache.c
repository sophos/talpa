/*
 * cache.c
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

#define TALPA_SUBSYS "cache"
#include "common/talpa.h"
#include "cache.h"

#include "platform/alloc.h"

#define TALPA_CACHE_UNLOCKED(lockname)     TALPA_RW_UNLOCKED(lockname)
#define talpa_cache_lock_init    talpa_rw_init
#define talpa_cache_read_lock    talpa_read_lock
#define talpa_cache_read_unlock  talpa_read_unlock
#define talpa_cache_write_lock   talpa_write_lock
#define talpa_cache_write_unlock talpa_write_unlock

/*
 * Forward declare implementation methods.
 */
static int find(const void* self, const uint32_t keyH, const uint32_t keyL);
static void add(void *self, const char* class, const uint32_t keyH, const uint32_t keyL);
static void clear(void *self, const uint32_t keyH, const uint32_t keyL);
static void purge(void *self, const uint32_t keyH);


static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);

static void deleteCache(struct tag_Cache* object);

static CacheConfigObject* findObject(const void* self, talpa_list_head* list, const char* value);
static void freeObject(CacheConfigObject* obj);
static void deleteObject(void *self, CacheConfigObject* obj);

static int allocateCache(void* self, unsigned int entries);
static void freeCache(void* self);


/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_STAT            "stats"
#define CFG_FSTYPES         "fstypes"
#define CFG_PARAMS          "params"

#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_VALUE_DUMMY     "(dummy)"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"

/*
 * Template Object.
 */
static Cache template_Cache =
    {
        {
            find,
            add,
            clear,
            purge,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteCache
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteCache
        },
        deleteCache,
        false,
        TALPA_CACHE_UNLOCKED(talpa_cache_lock),
        0,
        NULL,
        2,
        24989,
        12491,
        0,
        0,
        0,
        0,
        TALPA_RCU_UNLOCKED(talpa_cache_config_lock),
        TALPA_MUTEX_INIT,
        { },
        NULL,
        {
            {NULL, NULL, CACHE_CFGDATASIZE, true, true },
            {NULL, NULL, CACHE_STATDATASIZE, false, true },
            {NULL, NULL, CACHE_FSCFGDATASIZE, true, true },
            {NULL, NULL, CACHE_PARAMSCFGDATASIZE, true, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_DISABLED },
        { CFG_STAT, CFG_VALUE_DUMMY },
        { CFG_FSTYPES, CFG_VALUE_DUMMY },
        { CFG_PARAMS, CFG_VALUE_DUMMY }
    };
#define this    ((Cache*)self)

/*
 * Object creation/destruction.
 */
Cache* newCache(void)
{
    Cache* object;


    object = talpa_alloc(sizeof(template_Cache));
    if ( object )
    {
        unsigned int i;


        memcpy(object, &template_Cache,sizeof(template_Cache));

        object->i_ICache.object = object->i_IConfigurable.object = object;

        object->mConfig[0].name  = object->mStateConfigData.name;
        object->mConfig[0].value = object->mStateConfigData.value;
        object->mConfig[1].name  = object->mStatisticsData.name;
        object->mConfig[1].value = object->mStatisticsData.value;
        object->mConfig[2].name  = object->mFSConfigData.name;
        object->mConfig[2].value = object->mFSConfigData.value;
        object->mConfig[3].name  = object->mParamsConfigData.name;
        object->mConfig[3].value = object->mParamsConfigData.value;

        if ( !allocateCache(object, object->mEntries) )
        {
            talpa_free(object);
            return NULL;
        }

        for ( i = 0; i < object->mEntries; i++ )
        {
            object->mCache[i].device = -1;
            object->mCache[i].inode = 0;
        }

        sprintf(object->mParamsConfigData.value, "%u,%u,%u", object->mEntries, object->mPrime, object->mSetSize);

        talpa_cache_lock_init(&object->mCacheLock);
        talpa_rcu_lock_init(&object->mConfigLock);
        talpa_mutex_init(&object->mConfigSerialize);
        TALPA_INIT_LIST_HEAD(&object->mFilesystems);

    }
    return object;
}

static int allocateCache(void* self, unsigned int entries)
{
    unsigned int size;
    void* cache;

    size = entries * sizeof(struct CacheEntry);

    if ( size > (128*1024) )
    {
        cache = talpa_large_alloc(size);
        dbg("Vallocation of %u bytes returned 0x%p", size, cache);
    }
    else
    {
        cache = talpa_alloc(size);
        dbg("Kallocation of %u bytes returned 0x%p", size, cache);
    }

    if ( !cache )
    {
        size = 0;
        err("Cache allocation failed!");
    }

    this->mCacheBytes = size;
    this->mCache = (struct CacheEntry *)cache;

    return size;
}

static void freeCache(void* self)
{
    if ( this->mCacheBytes > (128*1024) )
    {
        talpa_large_free(this->mCache);
    }
    else
    {
        talpa_free(this->mCache);
    }

    this->mCache = NULL;
    this->mCacheBytes = 0;

    return;
}

static void deleteCache(struct tag_Cache* object)
{
    CacheConfigObject *obj, *tmp;

    talpa_rcu_synchronize();

    talpa_rcu_write_lock(&object->mConfigLock);
    talpa_list_for_each_entry_safe(obj, tmp, &object->mFilesystems, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }
    talpa_free(object->mFilesystemsSet);
    talpa_rcu_write_unlock(&object->mConfigLock);

    freeCache(object);
    talpa_free(object);

    return;
}

/*
 * IInterceptFilter.
 */

/* Returns 1 if the filesystem is on the list */
static inline int checkFilesystem(const void* self, const char* fstype)
{
    if ( likely(fstype != NULL) )
    {
        CacheConfigObject *obj;
        unsigned int len;

        len = strlen(fstype);
        talpa_rcu_read_lock(&this->mConfigLock);
        talpa_list_for_each_entry_rcu(obj, &this->mFilesystems, head)
        {
            if ( (len == obj->len) && !strcmp(fstype, obj->string) )
            {
                talpa_rcu_read_unlock(&this->mConfigLock);
                return 1;
            }
        }
        talpa_rcu_read_unlock(&this->mConfigLock);
    }

    return 0;
}

static int find(const void* self, const uint32_t keyH, const uint32_t keyL)
{
    /* See if we have a entry in the cache? */

    int entries;
    int set;
    int prime;
    int pass;
    int first;
    int modulo;
    int index;
    struct CacheEntry* cache;

    talpa_cache_read_lock(&this->mCacheLock);

    entries = this->mEntries;
    set = this->mSetSize;
    prime = this->mPrime;
    cache = this->mCache;

    first = (( keyH % entries ) * ( keyL % entries )) % entries;
    pass = 0;
    modulo = (( keyH % prime ) * ( keyL % prime )) % prime + 1;
    index = first;

    while ( pass < set )
    {
        if ( (cache[index].device == keyH) && (cache[index].inode == keyL) )
        {
            /* We have a hit! */
            this->mHits++;
            if ( !this->mHits )
            {
                this->mMisses = 0;
            }
            talpa_cache_read_unlock(&this->mCacheLock);
            return 1;
        }
        index = ( index + modulo ) % entries;
        pass++;
    }

    /* Since we didn't find the file in the cache, let
        the other filters decide what to do. */
    this->mMisses++;
    if ( !this->mMisses )
    {
        this->mHits = 0;
    }

    talpa_cache_read_unlock(&this->mCacheLock);

    return 0;
}

static void add(void *self, const char* class, const uint32_t keyH, const uint32_t keyL)
{
    int entries;
    int set;
    int prime;
    int pass;
    int first;
    int modulo;
    int index;
    struct CacheEntry* cache;

    /* Check whether we should try to cache this fs */
    if ( !checkFilesystem(this, class) )
    {
        return;
    }

    talpa_cache_write_lock(&this->mCacheLock);

    entries = this->mEntries;
    set = this->mSetSize;
    prime = this->mPrime;
    cache = this->mCache;

    first = (( keyH % entries ) * ( keyL % entries )) % entries;
    modulo = (( keyH % prime ) * ( keyL % prime )) % prime + 1;

    pass = 0;
    index = first;

    while ( pass < set )
    {
        if ( (cache[index].device == -1) && (cache[index].inode == 0) )
        {
            cache[index].device = keyH;
            cache[index].inode = keyL;
            this->mFill++;
            talpa_cache_write_unlock(&this->mCacheLock);
            return;
        }
        else if ( (cache[index].device == keyH) && (cache[index].inode == keyL) )
        {
            /* Multiple concurrent scan can happen and they will be serialised
               by the cache lock. Therefore adding the same entry for the second
               time must be avoided. Nothing bad can happen from concurrent scans
               except it's not the most optimal scenario. But it would be even
               worse for performance to introduce something smarter for that
               exceptional event. */
            talpa_cache_write_unlock(&this->mCacheLock);
            dbg("Duplicate add attempted!");
            return;
        }
        index = ( index + modulo ) % entries;
        pass++;
    }

    if ( pass >= set )
    {
      index = ( first + ( this->mReplacement % set ) * modulo ) % entries;
      this->mReplacement++;
      cache[index].device = keyH;
      cache[index].inode = keyL;
    }

    talpa_cache_write_unlock(&this->mCacheLock);

    return;
}

static void clear(void *self, const uint32_t keyH, const uint32_t keyL)
{
    int entries;
    int set;
    int prime;
    int pass;
    int first;
    int modulo;
    int index;
    struct CacheEntry* cache;

    talpa_cache_write_lock(&this->mCacheLock);

    entries = this->mEntries;
    set = this->mSetSize;
    prime = this->mPrime;
    cache = this->mCache;

    first = (( keyH % entries ) * ( keyL % entries )) % entries;
    pass = 0;
    modulo = (( keyH % prime ) * ( keyL % prime )) % prime + 1;
    index = first;

    while ( pass < set )
    {
        if ( (cache[index].device == keyH) && (cache[index].inode == keyL) )
        {
            /* Delete the entry from the cache */
            cache[index].device = -1;
            cache[index].inode = 0;
            this->mFill--;
            break;
        }
        index = ( index + modulo ) % entries;
        pass++;
    }

    talpa_cache_write_unlock(&this->mCacheLock);

    return;
}

static void purge(void *self, const uint32_t keyH)
{
    unsigned int entry;
    unsigned int entries;
    unsigned int fill;
    struct CacheEntry* cache;

    talpa_cache_write_lock(&this->mCacheLock);

    entries = this->mEntries;
    fill = this->mFill;
    cache = this->mCache;

    for ( entry = 0; entry < entries; entry++ )
    {
        if ( cache[entry].device == keyH )
        {
            cache[entry].device = -1;
            cache[entry].inode = 0;
            fill--;
        }
    }

    this->mFill = fill;

    talpa_cache_write_unlock(&this->mCacheLock);

    return;
}

/*
 * configuration list handling & objects
 */

static CacheConfigObject* newObject(void *self, const char* string)
{
    CacheConfigObject* obj = NULL;

    obj = talpa_alloc(sizeof(CacheConfigObject));

    if ( obj )
    {
        obj->len = strlen(string);
        obj->string = talpa_alloc(obj->len + 1);
        if ( !obj->string )
        {
            talpa_free(obj);
            return NULL;
        }
        strcpy(obj->string, string);
    }

    return obj;
}

static void freeObject(CacheConfigObject* obj)
{
    talpa_free(obj->string);
    talpa_free(obj);

    return;
}

static void deleteObject(void *self, CacheConfigObject* obj)
{
    talpa_rcu_synchronize();
    freeObject(obj);

    return;
}

static void constructStringSet(const void* self, talpa_list_head* list, char** set)
{
    unsigned int len;
    unsigned int alloc_len = 0;
    CacheConfigObject* obj;
    char* newset = NULL;
    char* out;


    /* We are doing the allocation in at least 2-passes.
     * That is because we want to allocate enough storage outside of
     * the lock holding section. */
try_alloc:
    /* We do not allocate anything in first pass. */
    if ( alloc_len )
    {
        newset = talpa_alloc(alloc_len);
        if ( !newset )
        {
            err("Failed to create string set!");
            return;
        }
    }

    len = 0;
    talpa_rcu_read_lock(&this->mConfigLock);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        len += obj->len + 1;
    }

    /* We will reallocate if the size has increased or this is a second pass (first allocation)/ */
    if ( (len + 1) > alloc_len )
    {
        talpa_rcu_read_unlock(&this->mConfigLock);
        alloc_len = len + 1;
        talpa_free(newset);
        goto try_alloc;
    }

    out = newset;
    talpa_free(*set);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        strcpy(out, obj->string);
        out += obj->len;
        *out++ = '\n';
    }
    if ( out > newset )
    {
        out--;
    }
    *out = 0;
    *set = newset;

    talpa_rcu_read_unlock(&this->mConfigLock);

    return;
}

static void destroyStringSet(void *self, char **set)
{
    talpa_free(*set);
    *set = NULL;
    return;
}

static CacheConfigObject* findObject(const void* self, talpa_list_head* list, const char* value)
{
    CacheConfigObject *obj;

    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        if ( !strcmp(obj->string, value) )
        {
            return obj;
        }
    }

    return NULL;
}

static CacheConfigObject* appendObject(void* self, talpa_list_head* list, const char* value)
{
    CacheConfigObject *obj;

    talpa_rcu_read_lock(&this->mConfigLock);
    obj = findObject(this, list, value);
    talpa_rcu_read_unlock(&this->mConfigLock);
    if ( obj )
    {
        dbg("String already in list!");
        return obj;
    }
    /* No problem here since appends and removes happen from userspace
     * which is serialised. */
    obj = newObject(this, value);
    if ( obj )
    {
        talpa_rcu_write_lock(&this->mConfigLock);
        talpa_list_add_tail_rcu(&obj->head, list );
        talpa_rcu_write_unlock(&this->mConfigLock);
        dbg("%s added", value);
    }

    return obj;
}

static bool removeObject(void *self, talpa_list_head* list, const char* value)
{
    CacheConfigObject *obj;

    talpa_rcu_write_lock(&this->mConfigLock);
    obj = findObject(this, list, value);
    if ( obj )
    {
        talpa_list_del_rcu(&obj->head);
        talpa_rcu_write_unlock(&this->mConfigLock);
        deleteObject(this, obj);
        dbg("%s removed", value);
        return true;
    }
    talpa_rcu_write_unlock(&this->mConfigLock);

    return false;
}

static void doActionString(void* self, talpa_list_head* list, char** set, const char* value)
{
    if ( strlen(value) < 2 )
    {
        return;
    }

    if ( value[0] == '+' )
    {
        appendObject(this, list, &value[1]);
    }
    else if ( value[0] == '-' )
    {
        removeObject(this, list, &value[1]);
    }
    destroyStringSet(this, set);

    return;
}

/* Integer binary exponent approximation function borrowed
   from drivers/net/hamradio/soundmodem/sm_afsk2666.c */
static int binexp(unsigned int i)
{
    int ret = 31;

    if (!i)
        return 0;
    if (i < 0x10000LU) {
        i <<= 16;
        ret -= 16;
    }
    if (i < 0x1000000LU) {
        i <<= 8;
        ret -= 8;
    }
    if (i < 0x10000000LU) {
        i <<= 4;
        ret -= 4;
    }
    if (i < 0x40000000LU) {
        i <<= 2;
        ret -= 2;
    }
    if (i < 0x80000000LU)
        ret -= 1;
    return ret;
}

static const unsigned int sqrt_tab[16] = {
    00000, 16384, 23170, 28378, 32768, 36636, 40132, 43348,
    46341, 49152, 51811, 54340, 56756, 59073, 61303, 63455
};


static unsigned int int_sqrt_approx(unsigned int i)
{
    unsigned int j;

    if (i < 16)
            return sqrt_tab[i] >> 14;
    j = binexp(i) >> 1;
    i >>= (j * 2 - 2);
    return (sqrt_tab[i & 0xf] << j) >> 15;
}

/* End of borrowed code */

/* Find next prime lower than number given */
static int findPrime(int inval)
{
    int i;
    int retval = inval;
    int max = int_sqrt_approx(inval);

    while( max <= retval )
    {
        i = 2;
        while ( i <= max )
        {
            if ( (retval % i) == 0 )
            {
                --retval;
                break;
            }
            i++;
            if ( (i & 1) == 0 )
            {
                i++;
            }
            if (i > max) {
                return retval;
            }
        }
    }

    dbg("Failed to find prime lower than %d", inval);
    return 0;
}

static int calculateCacheParams(unsigned int* entries, unsigned int* hash, unsigned int* setsize)
{
    int temp_entries;
    int temp_prime;
    int temp_set;

    temp_entries = *entries;

    if ( temp_entries < 10 )
    {
        err("Cache size to small!");
        return 0;
    }

    temp_entries = findPrime(temp_entries);

    if ( !temp_entries )
    {
        err("Failed to find 1st hash prime!");
        return 0;
    }

    temp_set = 2;
    temp_prime = ( temp_entries + temp_set - 2 ) / temp_set;

    if ( *setsize )
    {
        temp_set = *setsize;

        if ( temp_set < 1 )
        {
            temp_set = 1;
        }
    }

    if ( *hash )
    {
        temp_prime = *hash;

        if (    ( temp_prime >= temp_entries ) ||
                ( temp_prime < 1 ) ||
                ( ( temp_set > 2) && ( temp_prime >= ( temp_entries / ( temp_set - 1 ) ) ) )    )
        {
            if ( temp_set > 2 )
            {
                temp_prime = temp_entries / ( temp_set - 1 );
            }
            else
            {
                temp_prime = temp_entries - 1;
            }
        }
    }

    temp_prime = findPrime(temp_prime);

    if ( !temp_prime )
    {
        err("Failed to find 2nd hash prime!");
        return 0;
    }

    dbg("Cache size %u, 2nd hash prime %u, set size %u", temp_entries, temp_prime, temp_set);

    *entries = temp_entries;
    *hash = temp_prime;
    *setsize = temp_set;

    return 1;
}

static void configureCache(void* self, const char *string)
{
    const char* entries_string;
    char* prime_string;
    char* set_string;

    unsigned int entries = 0;
    unsigned int prime = 0;
    unsigned int set = 0;

    char* res;


    if ( this->mEnabled )
    {
        notice("Cannot configure cache while enabled!");
        return;
    }

    entries_string = string;
    prime_string = strchr(entries_string, ',');
    if ( prime_string )
    {
        *prime_string++ = 0;
        set_string = strchr(prime_string, ',');
        if ( set_string )
        {
            *set_string++ = 0;
            set = simple_strtoul(set_string, &res, 10);
        }
        prime = simple_strtoul(prime_string, &res, 10);
    }
    entries = simple_strtoul(entries_string, &res, 10);
    if ( calculateCacheParams(&entries, &prime, &set) )
    {
        freeCache(this);
        if ( allocateCache(this, entries) )
        {
            this->mEntries = entries;
            this->mPrime = prime;
            this->mSetSize = set;
            sprintf(this->mParamsConfigData.value, "%u,%u,%u", this->mEntries, this->mPrime, this->mSetSize);
            notice("Cache now has %u entries, %u-way associated, 2nd hash prime is %u", entries, set, prime);
        }
    }

    return;
}

static bool enable(void* self)
{
    if ( !this->mEnabled && this->mCache )
    {
        unsigned int i;

        for ( i = 0; i < this->mEntries; i++ )
        {
            this->mCache[i].device = -1;
            this->mCache[i].inode = 0;
        }

        this->mHits = this->mMisses = this->mReplacement = this->mFill = 0;

        this->mEnabled = true;
        strcpy(this->mStateConfigData.value, CFG_VALUE_ENABLED);
        info("Enabled");
    }
    return true;
}

static void disable(void* self)
{
    if (this->mEnabled)
    {
        this->mHits = this->mMisses = this->mReplacement = this->mFill = 0;
        this->mEnabled = false;
        strcpy(this->mStateConfigData.value, CFG_VALUE_DISABLED);
        info("Disabled");
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mEnabled;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "Cache";
}

static const PODConfigurationElement* allConfig(const void* self)
{
    return this->mConfig;
}

static const char* config(const void* self, const char* name)
{
    PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Return what was found else a null pointer.
     */
    if ( cfgElement->name )
    {
        char* retstring = cfgElement->value;


        talpa_mutex_lock(&this->mConfigSerialize);

        if ( !strcmp(cfgElement->name, CFG_STAT) )
        {
            /* 5 unsigned ints + 53 text chars = 5*10 + 53 = 103 characters.
               Although cache size (total, fill) can't be as big as UINT_MAX,
               we will assume it can. Check CACHE_STATDATASIZE if you modify
               something here. */
            sprintf(cfgElement->value, "Hits: %u, Misses: %u\nUsed: %u, Replacements: %u, Total: %u", this->mHits, this->mMisses, this->mFill, this->mReplacement, this->mEntries);
        }
        else if ( !strcmp(cfgElement->name, CFG_FSTYPES) )
        {
            if ( !this->mFilesystemsSet )
            {
                constructStringSet(this, &this->mFilesystems, &this->mFilesystemsSet);
            }
            retstring = this->mFilesystemsSet;
        }

        talpa_mutex_unlock(&this->mConfigSerialize);

        return retstring;
    }
    return NULL;
}

static void  setConfig(void* self, const char* name, const char* value)
{
   PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Cant set that which does not exist!
     */
    if ( !cfgElement->name )
    {
        return;
    }

    /*
     * OK time to do some work...
     */

    talpa_mutex_lock(&this->mConfigSerialize);

    if (strcmp(name, CFG_STATUS) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            enable(this);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            disable(this);
        }
    }
    else if ( !strcmp(name, CFG_FSTYPES) )
    {
        doActionString(this, &this->mFilesystems, &(this->mFilesystemsSet), value);
    }
    else if ( !strcmp(cfgElement->name, CFG_PARAMS) )
    {
        configureCache(this, value);
    }

    talpa_mutex_unlock(&this->mConfigSerialize);

    return;
}

/*
 * End of cache.c
 */

