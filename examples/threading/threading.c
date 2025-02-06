#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    // Wait, obtain mutex, wait, release mutex as described by thread_data structure
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    thread_func_args->thread_complete_success = false;

    usleep(thread_func_args->wait_to_obtain_ms * 1000);

    if (pthread_mutex_lock(thread_func_args->mutex) == 0)
    {
        usleep(thread_func_args->wait_to_release_ms * 1000);

        if (pthread_mutex_unlock(thread_func_args->mutex) == 0)
        {
            thread_func_args->thread_complete_success = true;
        }
    }

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * Allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    if (thread == NULL || mutex == NULL)
    {
        ERROR_LOG("Invalid input parameters");
        return false;
    }

    struct thread_data* thread_data = malloc(sizeof(struct thread_data));

    if (thread_data == NULL)
    {
        ERROR_LOG("Memory allocation of thread_data failed");
        return false;
    }

    thread_data->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_data->wait_to_release_ms = wait_to_release_ms;
    thread_data->mutex = mutex;

    if (pthread_create(thread, NULL, threadfunc, thread_data) != 0)
    {
        ERROR_LOG("Thread creation failed");
        free(thread_data);
        return false;
    }

    return true;
}

