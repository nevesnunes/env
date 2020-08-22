package app;

import java.io.*; 
import java.util.*; 
import java.util.concurrent.*; 
import java.util.concurrent.locks.*; 

public class ReentrantDeadlock {
    private static ReentrantLock lock = new ReentrantLock();
    public static void main(String args[]) {
        CountDownLatch latch = new CountDownLatch(2);
        Thread taker1 = new Thread() {
            public void run() {
                latch.countDown();
                try {
                    latch.await();
                } catch (InterruptedException e) {
                }
                lock.lock();
                System.out.println("1");
                lock.lock();
                System.out.println("1b");
            }
        };
        Thread taker2 = new Thread() {
            public void run() {
                latch.countDown();
                try {
                    latch.await();
                } catch (InterruptedException e) {
                }
                lock.lock();
                System.out.println("2");
                lock.lock();
                System.out.println("2b");
            }
        };
        taker1.start();
        taker2.start();
    }
}

