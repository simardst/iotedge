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
        IDictionary<string, StoredServiceIdentity> serviceIdentityCache;
        readonly Timer refreshCacheTimer;
        Task refreshCacheTask;

        public event EventHandler<ServiceIdentity> ServiceIdentityUpdated;
        public event EventHandler<string> ServiceIdentityRemoved;

        SecurityScopeEntitiesCache(IServiceProxy serviceProxy,
            IEncryptedStore<string, string> encryptedStorage,
            IDictionary<string, StoredServiceIdentity> initialCache)
        {
            this.serviceProxy = serviceProxy;
            this.encryptedStore = encryptedStorage;
            this.serviceIdentityCache = initialCache;
            this.refreshCacheTimer = new Timer(this.RefreshCache, null, TimeSpan.Zero, TimeSpan.FromHours(1));
        }

        public static async Task<SecurityScopeEntitiesCache> Create(IServiceProxy serviceProxy, IEncryptedStore<string, string> encryptedStorage)
        {
            Preconditions.CheckNotNull(serviceProxy, nameof(serviceProxy));
            Preconditions.CheckNotNull(encryptedStorage, nameof(encryptedStorage));

            IDictionary<string, StoredServiceIdentity> cache = await ReadCacheFromStore(encryptedStorage);
            return new SecurityScopeEntitiesCache(serviceProxy, encryptedStorage, cache);
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
            try
            {
                IEnumerable<string> currentCacheIds = new List<string>(this.serviceIdentityCache.Keys);
                ISecurityScopeIdentitiesIterator iterator = this.serviceProxy.GetSecurityScopeIdentitiesIterator();
                while (iterator.HasNext)
                {
                    IEnumerable<ServiceIdentity> batch = await iterator.GetNext();
                    foreach (ServiceIdentity serviceIdentity in batch)
                    {
                        await this.HandleNewServiceIdentity(serviceIdentity);
                    }
                }

                // Diff and update
                IEnumerable<string> removedIds = currentCacheIds.Except(this.serviceIdentityCache.Keys);
                await Task.WhenAll(removedIds.Select(id => this.HandleNoServiceIdentity(id)));
            }
            catch (Exception)
            {
                // Log
            }
        }

        public async Task RefreshCache(string deviceId)
        {
            Option<ServiceIdentity> serviceIdentity = await this.serviceProxy.GetServiceIdentity(deviceId);
            await serviceIdentity
                .Map(this.HandleNewServiceIdentity)
                .GetOrElse(this.HandleNoServiceIdentity(deviceId));
        }

        public async Task RefreshCache(string deviceId, string moduleId)
        {
            Option<ServiceIdentity> serviceIdentity = await this.serviceProxy.GetServiceIdentity(deviceId, moduleId);
            await serviceIdentity
                .Map(this.HandleNewServiceIdentity)
                .GetOrElse(this.HandleNoServiceIdentity($"{deviceId}/{moduleId}"));
        }

        public async Task RefreshCache(IEnumerable<string> deviceIds)
        {
            Preconditions.CheckNotNull(deviceIds, nameof(deviceIds));
            foreach (string deviceId in deviceIds)
            {
                await this.RefreshCache(deviceId);
            }
        }

        async Task HandleNoServiceIdentity(string id)
        {
            var storedServiceIdentity = new StoredServiceIdentity(id);
            this.serviceIdentityCache[id] = storedServiceIdentity;
            await this.SaveServiceIdentityToStore(id, storedServiceIdentity);

            // Remove device if connected
            this.ServiceIdentityRemoved?.Invoke(this, id);
        }

        async Task HandleNewServiceIdentity(ServiceIdentity serviceIdentity)
        {
            // lock?
            bool hasUpdated = !this.CompareWithCacheValue(serviceIdentity);
            var storedServiceIdentity = new StoredServiceIdentity(serviceIdentity);
            this.serviceIdentityCache[serviceIdentity.Id] = storedServiceIdentity;
            await this.SaveServiceIdentityToStore(serviceIdentity.Id, storedServiceIdentity);

            if (hasUpdated)
            {
                this.ServiceIdentityUpdated?.Invoke(this, serviceIdentity);
            }
        }

        bool CompareWithCacheValue(ServiceIdentity serviceIdentity)
        {
            if (this.serviceIdentityCache.TryGetValue(serviceIdentity.Id, out StoredServiceIdentity currentStoredServiceIdentity))
            {
                return currentStoredServiceIdentity.ServiceIdentity
                    .Map(s => s.Equals(serviceIdentity))
                    .GetOrElse(false);
            }

            return false;
        }

        async Task SaveServiceIdentityToStore(string id, StoredServiceIdentity storedServiceIdentity)
        {
            string serviceIdentityString = JsonConvert.SerializeObject(storedServiceIdentity);
            await this.encryptedStore.Put(id, serviceIdentityString);
        }

        static async Task<IDictionary<string, StoredServiceIdentity>> ReadCacheFromStore(IEncryptedStore<string, string> encryptedStore)
        {
            IDictionary<string, StoredServiceIdentity> cache = new Dictionary<string, StoredServiceIdentity>();
            await encryptedStore.IterateBatch(
                int.MaxValue,
                (key, value) =>
                {
                    cache.Add(key, JsonConvert.DeserializeObject<StoredServiceIdentity>(value));
                    return Task.CompletedTask;
                });
            return cache;
        }

        public Task<Option<ServiceIdentity>> GetServiceIdentity(string id)
        {
            if (this.serviceIdentityCache.TryGetValue(id, out StoredServiceIdentity storedServiceIdentity))
            {
                return Task.FromResult(storedServiceIdentity.ServiceIdentity);
            }
            return Task.FromResult(Option.None<ServiceIdentity>());
        }

        public void Dispose()
        {
            this.encryptedStore?.Dispose();
            this.refreshCacheTimer?.Dispose();
            this.refreshCacheTask?.Dispose();
        }

        class StoredServiceIdentity
        {
            public StoredServiceIdentity(ServiceIdentity serviceIdentity)
                : this(Preconditions.CheckNotNull(serviceIdentity, nameof(serviceIdentity)).Id, serviceIdentity, DateTime.UtcNow)
            {
            }

            public StoredServiceIdentity(string id)
                : this(Preconditions.CheckNotNull(id, nameof(id)), null, DateTime.UtcNow)
            { }

            [JsonConstructor]
            public StoredServiceIdentity(string id, ServiceIdentity serviceIdentity, DateTime timestamp)
            {
                this.ServiceIdentity = Option.Maybe(serviceIdentity);
                this.Id = Preconditions.CheckNotNull(id);
                this.Timestamp = timestamp;
            }

            public Option<ServiceIdentity> ServiceIdentity { get; }

            public string Id { get; }

            public DateTime Timestamp { get; }
        }
    }
}
