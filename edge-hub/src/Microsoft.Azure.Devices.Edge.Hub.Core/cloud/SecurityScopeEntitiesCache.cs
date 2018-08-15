// Copyright (c) Microsoft. All rights reserved.
namespace Microsoft.Azure.Devices.Edge.Hub.Core.Cloud
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Devices.Edge.Storage;
    using Microsoft.Azure.Devices.Edge.Util;
    using Microsoft.Azure.Devices.Edge.Util.Concurrency;
    using Newtonsoft.Json;

    public sealed class SecurityScopeEntitiesCache : ISecurityScopeEntitiesCache
    {
        readonly IServiceProxy serviceProxy;
        readonly IEncryptedStore<string, string> encryptedStore;
        readonly AsyncLock asyncLock = new AsyncLock();
        IDictionary<string, ServiceIdentity> serviceIdentityCache;
        readonly Timer refreshCacheTimer;
        Task refreshCacheTask;

        public SecurityScopeEntitiesCache(IServiceProxy serviceProxy, IEncryptedStore<string, string> encryptedStorage)
        {
            this.serviceProxy = serviceProxy;
            this.encryptedStore = encryptedStorage;
            this.serviceIdentityCache = new Dictionary<string, ServiceIdentity>();
            this.refreshCacheTimer = new Timer(this.RefreshCache, null, TimeSpan.Zero, TimeSpan.FromHours(1));
        }

        void RefreshCache(object state)
        {
            if (this.refreshCacheTask == null || this.refreshCacheTask.IsCompleted)
            {
                this.refreshCacheTask = this.RefreshCache();
            }
        }

        public async Task RefreshCache()
        {
            using (await this.asyncLock.LockAsync())
            {
                IDictionary<string, ServiceIdentity> cache = await this.ReadCacheFromStore();
                try
                {
                    ISecurityScopeIdentitiesIterator iterator = this.serviceProxy.GetSecurityScopeIdentitiesIterator();
                    while (iterator.HasNext)
                    {
                        IEnumerable<ServiceIdentity> batch = await iterator.GetNext();
                        foreach (ServiceIdentity serviceIdentity in batch)
                        {
                            cache[serviceIdentity.Id] = serviceIdentity;
                            await this.SaveServiceIdentityToStore(serviceIdentity.Id, serviceIdentity);
                        }
                    }
                }
                catch (Exception)
                {
                    // Log
                }

                // Diff and update

                this.serviceIdentityCache = cache;
            }
        }

        public async Task RefreshCache(IEnumerable<string> deviceIds)
        {
            using (await this.asyncLock.LockAsync())
            {

            }
        }

        async Task SaveServiceIdentityToStore(string id, ServiceIdentity serviceIdentity)
        {
            string serviceIdentityString = JsonConvert.SerializeObject(serviceIdentity);
            await this.encryptedStore.Put(id, serviceIdentityString);
        }

        async Task<IDictionary<string, ServiceIdentity>> ReadCacheFromStore()
        {
            IDictionary<string, ServiceIdentity> cache = new Dictionary<string, ServiceIdentity>();
            await this.encryptedStore.IterateBatch(
                int.MaxValue,
                (key, value) =>
                {
                    cache.Add(key, JsonConvert.DeserializeObject<ServiceIdentity>(value));
                    return Task.CompletedTask;
                });
            return cache;
        }

        public Task<Option<ServiceIdentity>> GetServiceIdentity(string id)
        {
            if (this.serviceIdentityCache.TryGetValue(id, out ServiceIdentity serviceIdentity))
            {
                return Task.FromResult(Option.Some(serviceIdentity));
            }
            return Task.FromResult(Option.None<ServiceIdentity>());
        }

        public void Dispose()
        {
            this.encryptedStore?.Dispose();
            this.refreshCacheTimer?.Dispose();
            this.refreshCacheTask?.Dispose();
        }

        class Refresher
        {
            bool refreshAll;
            ISet<string> deviceIds = new HashSet<string>();
            readonly AsyncLock addWorkLock = new AsyncLock();
            Task refreshCacheTask;
            readonly IServiceProxy serviceProxy;
            readonly IEncryptedStore<string, string> encryptedStore;
            readonly AsyncLock asyncLock = new AsyncLock();
            IDictionary<string, ServiceIdentity> serviceIdentityCache;

            public Refresher(IServiceProxy serviceProxy,
                IEncryptedStore<string, string> encryptedStorage,
                IDictionary<string, ServiceIdentity> serviceIdentityCache)
            {
                this.serviceProxy = serviceProxy;
                this.encryptedStore = encryptedStorage;
                this.serviceIdentityCache = serviceIdentityCache;
            }

            public async Task Refresh(Option<IEnumerable<string>> deviceIds)
            {
                using (await this.addWorkLock.LockAsync())
                {
                    if (!deviceIds.HasValue)
                    {
                        this.refreshAll = true;
                    }
                    else
                    {
                        deviceIds.ForEach(
                            d =>
                            {
                                foreach (string id in d)
                                {
                                    this.deviceIds.Add(id);
                                }
                            });
                    }

                    if (this.refreshCacheTask == null || this.refreshCacheTask.IsCompleted)
                    {
                        this.refreshCacheTask = this.StartWork();
                    }                    
                }
            }

            async Task StartWork()
            {
                while (true)
                {
                    Task work;
                    using(await this.addWorkLock.LockAsync())
                    if (this.deviceIds == null || this.deviceIds.Count > 0)
                    {
                        ISet<string> deviceIdsToProcess = this.deviceIds;
                        this.deviceIds = new HashSet<string>();
                        work = this.ProcessDeviceIds(deviceIdsToProcess);
                    }
                    else if (this.refreshAll)
                    {
                        this.refreshAll = false;
                        work = this.ProcessAll();
                    }
                    else
                    {
                        break;
                    }

                    await (work ?? Task.CompletedTask);
                }
            }

            Task ProcessAll()
            {
                throw new NotImplementedException();
            }

            Task ProcessDeviceIds(IEnumerable<string> deviceIdsToProcess)
            {
                throw new NotImplementedException();
            }
        }
    }
}
