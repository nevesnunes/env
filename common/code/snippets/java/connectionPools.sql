-- active shows the number of open/established connections (including inUse and idle)
-- checkedOut shows the reserved connections (owned by application components/clients of the pool)

-- SemaphoreConcurrentLinkedDequeManagedConnectionPool type
select p.pool.poolName.toString() AS poolName,
    p.checkedOutSize.value AS inUse,
    p.cls.size AS active,
    p.poolConfiguration.maxSize.value.toString() AS maxSize,
    p.poolConfiguration.minSize.value.toString() AS minSize,
    p.poolConfiguration.strictMin.value.toString() AS useStrictMin,
    p.poolConfiguration.prefill.value.toString() AS prefill
from org.jboss.jca.core.connectionmanager.pool.mcp.SemaphoreConcurrentLinkedDequeManagedConnectionPool p

-- SemaphoreArrayListManagedConnectionPool type
select p.pool.poolName.toString() AS poolName,
    p.checkedOut.size AS inUse,
    p.cls.size AS active,
    p.poolConfiguration.maxSize.value.toString() AS maxSize,
    p.poolConfiguration.minSize.value.toString() AS minSize,
    p.poolConfiguration.strictMin.value.toString() AS useStrictMin,
    p.poolConfiguration.prefill.value.toString() AS prefill
from org.jboss.jca.core.connectionmanager.pool.mcp.SemaphoreArrayListManagedConnectionPool p

-- LeakDumperManagedConnectionPool type
select p.pool.poolName.toString() AS poolName,
    p.checkedOut.size AS inUse,
    p.cls.size AS active,
    p.poolConfiguration.maxSize.value.toString() AS maxSize,
    p.poolConfiguration.minSize.value.toString() AS minSize,
    p.poolConfiguration.strictMin.value.toString() AS useStrictMin,
    p.poolConfiguration.prefill.value.toString() AS prefill
from org.jboss.jca.core.connectionmanager.pool.mcp.LeakDumperManagedConnectionPool p

-- Reference: https://access.redhat.com/solutions/309913
