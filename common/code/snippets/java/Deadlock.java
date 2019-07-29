public class Deadlock {
    private static Object obj1 = new Object();
    private static Object obj2 = new Object();

    public static void main(String[] args) {
        new Thread(new Thread1()).start();
        new Thread(new Thread2()).start();
    }

    private static class Thread1 implements Runnable {
        @Override
        public void run() {
            synchronized (obj1) {
                System.out.println("Thread1 got the lock for obj1!");

                try {
                    // The significance of 2 seconds pause is to let the Thread2 thread get the lock of obj2
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                synchronized (obj2) {
                    System.out.println("Thread1 got the lock for obj2!");
                }
            }
        }
    }

    private static class Thread2 implements Runnable {
        @Override
        public void run() {
            synchronized (obj2) {
                System.out.println("Thread2 got the lock for obj2!");

                try {
                    // The meaning of 2 seconds pause is to let the Thread1 thread get the lock of obj1
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                synchronized (obj1) {
                    System.out.println("Thread2 got the lock for obj1!");
                }
            }
        }
    }
}
