"""
Async Task Engine - High-performance concurrency control with graceful shutdown
"""

import asyncio
import time
import json
import os
from typing import Dict, List, Any, Callable, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import weakref

# Import global shutdown event for immediate termination
try:
    from core.shutdown import shutdown_event
except ImportError:
    # Fallback for standalone usage
    shutdown_event = None

@dataclass
class TaskResult:
    """Task execution result"""
    task_id: str
    target: str
    module: str
    success: bool
    result: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: str = ""


@dataclass
class Checkpoint:
    """Scan checkpoint for resume functionality"""
    timestamp: str
    completed_tasks: Set[str]
    failed_tasks: Set[str]
    pending_tasks: List[str]
    total_targets: int
    scan_mode: str


class TaskEngine:
    """High-performance async task engine with intelligent scheduling"""
    
    def __init__(self, max_workers: int = 50, checkpoint_interval: int = 60,
                 checkpoint_file: str = "results/.checkpoint.json"):
        self.max_workers = max_workers
        self.checkpoint_interval = checkpoint_interval
        self.checkpoint_file = checkpoint_file
        
        # Task management
        self.task_queue = asyncio.Queue()
        self.active_tasks: Set[asyncio.Task] = set()
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        
        # Performance tracking
        self.start_time = time.time()
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.total_requests = 0
        
        # Rate limiting and throttling
        self.request_times: List[float] = []
        self.rate_limit_window = 60.0  # 1 minute window
        self.max_requests_per_minute = 1000
        
        # Adaptive rate limiting
        self.adaptive_rate_limit = 1000  # Current adaptive limit
        self.rate_limit_backoff = 5.0  # Cool-down period in seconds
        self.last_429_time = 0.0
        self.last_503_time = 0.0
        self.consecutive_errors = 0
        self.max_consecutive_errors = 3
        
        # Shutdown control
        self.shutdown_event = asyncio.Event()
        self.graceful_shutdown = False
        
        # Checkpoint system
        self.last_checkpoint_time = time.time()
        self.checkpoint_data: Optional[Checkpoint] = None
        
        # Memory management
        self.result_cache: Dict[str, TaskResult] = {}
        self.max_cache_size = 10000
        
    async def submit_task(self, task_id: str, target: str, module: str, 
                         coro: Callable, priority: int = 0) -> str:
        """Submit task to the execution queue"""
        
        # Check if already completed (resume functionality)
        if task_id in self.completed_tasks:
            return task_id
        
        # Create task wrapper
        task_wrapper = {
            'task_id': task_id,
            'target': target,
            'module': module,
            'coro': coro,
            'priority': priority,
            'submit_time': time.time()
        }
        
        # Add to queue
        await self.task_queue.put(task_wrapper)
        return task_id
    
    async def execute_tasks(self) -> List[TaskResult]:
        """Main task execution loop"""
        
        print(f"[+] Task engine started with {self.max_workers} workers")
        
        # Create worker tasks
        workers = [
            asyncio.create_task(self._worker(f"worker-{i}"))
            for i in range(self.max_workers)
        ]
        
        # Create monitoring task
        monitor_task = asyncio.create_task(self._monitor())
        
        try:
            # Wait for all tasks to complete or shutdown
            await asyncio.gather(*workers, monitor_task, return_exceptions=True)
            
        except Exception as e:
            print(f"[!] Task engine error: {e}")
            
        finally:
            # Save final checkpoint
            await self._save_checkpoint()
            
        # Return results
        return list(self.result_cache.values())
    
    async def _worker(self, worker_id: str):
        """Worker task that processes items from the queue"""
        
        while not self.shutdown_event.is_set():
            try:
                # Get task from queue with timeout
                task_wrapper = await asyncio.wait_for(
                    self.task_queue.get(), 
                    timeout=1.0
                )
                
                # Process task
                task = asyncio.create_task(
                    self._execute_task(task_wrapper, worker_id)
                )
                self.active_tasks.add(task)
                
                # Wait for completion
                try:
                    await task
                except Exception as e:
                    print(f"[!] Worker {worker_id} task failed: {e}")
                finally:
                    self.active_tasks.discard(task)
                    self.task_queue.task_done()
                    
            except asyncio.TimeoutError:
                # No tasks available, continue
                continue
            except Exception as e:
                print(f"[!] Worker {worker_id} error: {e}")
                
        print(f"[*] Worker {worker_id} shutting down")
    
    async def _execute_task(self, task_wrapper: Dict[str, Any], worker_id: str):
        """Execute individual task with error handling and rate limiting"""
        
        # Check for shutdown signal before starting
        if shutdown_event and shutdown_event.is_set():
            return
        
        task_id = task_wrapper['task_id']
        target = task_wrapper['target']
        module = task_wrapper['module']
        coro = task_wrapper['coro']
        
        # Rate limiting
        await self._rate_limit()
        
        start_time = time.time()
        
        try:
            # Check for shutdown before execution
            if shutdown_event and shutdown_event.is_set():
                return
            
            # Execute the coroutine
            if asyncio.iscoroutinefunction(coro):
                result = await coro()
            else:
                result = coro()
            
            # Create successful result
            task_result = TaskResult(
                task_id=task_id,
                target=target,
                module=module,
                success=True,
                result=result,
                execution_time=time.time() - start_time,
                timestamp=datetime.now().isoformat()
            )
            
            self.completed_tasks.add(task_id)
            self.tasks_completed += 1
            
        except Exception as e:
            # Create failed result
            task_result = TaskResult(
                task_id=task_id,
                target=target,
                module=module,
                success=False,
                result=None,
                error=str(e),
                execution_time=time.time() - start_time,
                timestamp=datetime.now().isoformat()
            )
            
            self.failed_tasks.add(task_id)
            self.tasks_failed += 1
            
            if not self.graceful_shutdown:
                print(f"[!] Task {task_id} failed: {e}")
        
        # Cache result
        self._cache_result(task_result)
        
        # Update statistics
        self.total_requests += 1
    
    async def _rate_limit(self):
        """Implement adaptive rate limiting to prevent overwhelming targets"""
        
        current_time = time.time()
        
        # Check for recent 429/503 errors and apply backoff
        time_since_429 = current_time - self.last_429_time
        time_since_503 = current_time - self.last_503_time
        
        if time_since_429 < self.rate_limit_backoff or time_since_503 < self.rate_limit_backoff:
            print(f"[*] Adaptive rate limiting active - cooling down for {self.rate_limit_backoff:.1f}s")
            await asyncio.sleep(self.rate_limit_backoff)
            # Reduce rate limit after backoff
            self.adaptive_rate_limit = max(100, self.adaptive_rate_limit // 2)
            return
        
        # Clean old request times
        self.request_times = [
            req_time for req_time in self.request_times
            if current_time - req_time < self.rate_limit_window
        ]
        
        # Use adaptive rate limit (reduced after errors)
        current_limit = min(self.max_requests_per_minute, self.adaptive_rate_limit)
        
        # Check if we need to wait
        if len(self.request_times) >= current_limit:
            # Calculate wait time
            oldest_request = min(self.request_times)
            wait_time = self.rate_limit_window - (current_time - oldest_request)
            
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        # Record this request
        self.request_times.append(current_time)
    
    def handle_rate_limit_error(self, status_code: int):
        """Handle HTTP rate limit errors (429, 503)"""
        current_time = time.time()
        
        if status_code == 429:  # Too Many Requests
            self.last_429_time = current_time
            self.consecutive_errors += 1
            print(f"[!] Rate limit detected (429) - applying backoff")
            
        elif status_code == 503:  # Service Unavailable
            self.last_503_time = current_time
            self.consecutive_errors += 1
            print(f"[!] Service unavailable (503) - applying backoff")
        
        # Reduce concurrency if too many consecutive errors
        if self.consecutive_errors >= self.max_consecutive_errors:
            self.max_workers = max(1, self.max_workers // 2)
            print(f"[!] Reducing concurrency to {self.max_workers} due to errors")
            self.consecutive_errors = 0
    
    def handle_success_response(self):
        """Handle successful responses to gradually restore rate limit"""
        # Gradually restore rate limit on success
        if self.adaptive_rate_limit < self.max_requests_per_minute:
            self.adaptive_rate_limit = min(self.max_requests_per_minute, self.adaptive_rate_limit + 10)
        
        # Reset consecutive errors on success
        if self.consecutive_errors > 0:
            self.consecutive_errors = max(0, self.consecutive_errors - 1)
    
    async def _monitor(self):
        """Monitor task execution and handle checkpoints"""
        
        while not self.shutdown_event.is_set():
            try:
                # Print progress
                self._print_progress()
                
                # Save checkpoint if needed
                current_time = time.time()
                if current_time - self.last_checkpoint_time >= self.checkpoint_interval:
                    await self._save_checkpoint()
                    self.last_checkpoint_time = current_time
                
                # Memory cleanup
                if len(self.result_cache) > self.max_cache_size:
                    self._cleanup_cache()
                
                await asyncio.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                print(f"[!] Monitor error: {e}")
                await asyncio.sleep(10)
    
    def _print_progress(self):
        """Print execution progress"""
        
        elapsed = time.time() - self.start_time
        total_tasks = self.tasks_completed + self.tasks_failed
        queue_size = self.task_queue.qsize()
        
        if total_tasks > 0:
            success_rate = (self.tasks_completed / total_tasks) * 100
            rate = total_tasks / elapsed if elapsed > 0 else 0
            
            print(f"[*] Progress: {total_tasks} tasks ({success_rate:.1f}% success) "
                  f"| Queue: {queue_size} | Rate: {rate:.1f} tasks/sec")
    
    def _cache_result(self, result: TaskResult):
        """Cache task result with memory management"""
        
        # Add to cache
        self.result_cache[result.task_id] = result
        
        # Remove oldest if cache is full
        if len(self.result_cache) > self.max_cache_size:
            oldest_keys = list(self.result_cache.keys())[:100]
            for key in oldest_keys:
                del self.result_cache[key]
    
    def _cleanup_cache(self):
        """Clean up old cache entries"""
        
        # Remove oldest 25% of entries
        cache_size = len(self.result_cache)
        if cache_size > 0:
            remove_count = cache_size // 4
            oldest_keys = list(self.result_cache.keys())[:remove_count]
            for key in oldest_keys:
                del self.result_cache[key]
    
    async def _save_checkpoint(self):
        """Save checkpoint for resume functionality"""
        
        try:
            # Get pending tasks
            pending_tasks = []
            temp_queue = asyncio.Queue()
            
            # Drain queue temporarily
            while not self.task_queue.empty():
                try:
                    task = self.task_queue.get_nowait()
                    pending_tasks.append(task['task_id'])
                    await temp_queue.put(task)
                except asyncio.QueueEmpty:
                    break
            
            # Restore queue
            while not temp_queue.empty():
                await self.task_queue.put(temp_queue.get_nowait())
            
            # Create checkpoint
            checkpoint = Checkpoint(
                timestamp=datetime.now().isoformat(),
                completed_tasks=self.completed_tasks.copy(),
                failed_tasks=self.failed_tasks.copy(),
                pending_tasks=pending_tasks,
                total_targets=len(self.completed_tasks) + len(self.failed_tasks) + len(pending_tasks),
                scan_mode="unknown"
            )
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.checkpoint_file), exist_ok=True)
            
            # Save to file
            with open(self.checkpoint_file, 'w') as f:
                json.dump(asdict(checkpoint), f, indent=2, default=str)
            
            print(f"[*] Checkpoint saved: {len(self.completed_tasks)} completed")
            
        except Exception as e:
            print(f"[!] Failed to save checkpoint: {e}")
    
    async def load_checkpoint(self) -> Optional[Checkpoint]:
        """Load checkpoint for resume functionality"""
        
        try:
            if not os.path.exists(self.checkpoint_file):
                return None
            
            with open(self.checkpoint_file, 'r') as f:
                data = json.load(f)
            
            checkpoint = Checkpoint(**data)
            
            # Restore state
            self.completed_tasks = set(checkpoint.completed_tasks)
            self.failed_tasks = set(checkpoint.failed_tasks)
            
            print(f"[*] Checkpoint loaded: {len(self.completed_tasks)} completed, "
                  f"{len(checkpoint.pending_tasks)} pending")
            
            return checkpoint
            
        except Exception as e:
            print(f"[!] Failed to load checkpoint: {e}")
            return None
    
    async def shutdown(self, graceful: bool = True):
        """Initiate graceful shutdown"""
        
        self.graceful_shutdown = graceful
        self.shutdown_event.set()
        
        if graceful:
            print("[*] Initiating graceful shutdown...")
            
            # Wait for active tasks to complete (with timeout)
            if self.active_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self.active_tasks, return_exceptions=True),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    print("[!] Graceful shutdown timeout, forcing exit")
        else:
            print("[*] Force shutdown initiated")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics"""
        
        elapsed = time.time() - self.start_time
        total_tasks = self.tasks_completed + self.tasks_failed
        
        return {
            'elapsed_time': elapsed,
            'tasks_completed': self.tasks_completed,
            'tasks_failed': self.tasks_failed,
            'total_tasks': total_tasks,
            'success_rate': (self.tasks_completed / total_tasks * 100) if total_tasks > 0 else 0,
            'tasks_per_second': total_tasks / elapsed if elapsed > 0 else 0,
            'active_workers': len(self.active_tasks),
            'queue_size': self.task_queue.qsize(),
            'cache_size': len(self.result_cache)
        }
