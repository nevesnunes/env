-- The MIT License (MIT)
--
-- Copyright (c) 2015 Nandor Kracser
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

-- Useful VisualVM OQL snippets
-- Tested with Java 7 Heap Dumps

-- Find big Collections
function isBigCollection(c) {
  return c.size > 1000;
}

filter(heap.objects('java.util.AbstractCollection'), isBigCollection);
filter(heap.objects('java.util.AbstractMap'), isBigCollection);

-- Find a bad hash function
function entryChainLength(entry) {
  var cur = entry;
  var i = 0;
  while (cur) {
    i++;
    cur = cur.next;
  }
  return i;
}

function hasLongEntryChain(hashmap) {
  var MAX_CHAIN_LENGTH = 8;
  if (hashmap.size == 0) return false;
  for (var i in hashmap.table) {
    if (hashmap.table[i] && entryChainLength(hashmap.table[i]) > MAX_CHAIN_LENGTH)
      return true;
  }
  return false;
}

-- Find cyclic HashMap instances
filter(heap.objects('java.util.HashMap'), hasLongEntryChain);

-- Have you ever seen a hanging hashmap.get(key) call?
-- http://mailinator.blogspot.com/2009/06/beautiful-race-condition.html
function isCyclicEntry(entry) {
  var tortoise = entry;
  var hare = entry.next;
  while (true) {
    if (identical(hare, tortoise)) return true;
    if (tortoise.next) tortoise = tortoise.next;
    else return false;
    if (hare.next && hare.next.next) hare = hare.next.next;
    else return false;
  }
}

function isCyclicHashMap(hashmap) {
  for (var i in hashmap.table) {
    var entry = hashmap.table[i];
    if (entry) {
      if (isCyclicEntry(entry)) return true;
    }
  }
  return false;
}

-- Find overallocated HashMaps
-- Here 'overallocated' means it has more than twice as many buckets as it
-- loadFactor suggests.
filter(heap.objects('java.util.HashMap'), isCyclicHashMap);
filter(heap.objects('java.util.HashMap'), 'it.table != null && (it.table.length > it.size * 2 / it.loadFactor)');

-- How much memory do we waste by ArrayLists
select l.elementData.length - l.size from java.util.ArrayList l

-- Find references of dead Threads
select t from java.lang.Thread t where t.threadStatus = t.State.TERMINATED

-- Source: https://gist.github.com/bonifaido/2464414
