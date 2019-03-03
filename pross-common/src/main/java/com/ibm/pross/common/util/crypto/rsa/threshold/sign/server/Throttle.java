package com.ibm.pross.common.util.crypto.rsa.threshold.sign.server;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Implements a throttle in which the method can only be called at most once
 * every rateLimit milliseconds
 */
public class Throttle {

	// Create an executor service that uses daemon threads
	private final static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, new ThreadFactory() {
		@Override
		public Thread newThread(Runnable r) {
			 Thread thread = Executors.defaultThreadFactory().newThread(r);
		      thread.setDaemon(true);
		      return thread;
		}});
	
	private final long rateLimit;
	private final Semaphore semaphore;

	public Throttle(final long rateLimit) {

		this.semaphore = new Semaphore(1);
		this.rateLimit = rateLimit;
	}

	public void performThrottledAction()
	{
		// Attempt to acquire lock
		try {
			this.semaphore.acquire(1);
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		
		// Task to release the lock
		final Runnable lockRelease = new Runnable() {
			public void run() {
				Throttle.this.semaphore.release(1);
			}
		};
		
		// Release lock automatically after a delay
		scheduler.schedule(lockRelease, rateLimit, TimeUnit.MILLISECONDS);
	}

}
