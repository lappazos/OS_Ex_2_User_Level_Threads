#include "uthreads.h"

#include <iostream>
#include <queue>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>

#define SECOND 1000000

static const char *const SYS_ERROR = "system error";

static const char *const NEG_TIME_ERR = "thread library error: negative quantum time";

static const char *const MAX_THREAD_ERR = "thread library error: reach max number of threads";

static const char *const NO_SUCH_THREAD_ERR = "thread library error: no such thread exists";

static const char *const NO_SUCH_PRIO_ERR = "thread library error: no such priority";

static const char *const MAIN_BLOCK_ERR = "thread library error: it's illegal to block the main thread";

static const char *const SIZE_ERR = "Invalid size";

using namespace std;


#ifdef __x86_64__
/* code for 64 bit Intel arch */

typedef unsigned long address_t;
#define JB_SP 6
#define JB_PC 7

/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%fs:0x30,%0\n"
                 "rol    $0x11,%0\n"
    : "=g" (ret)
    : "0" (addr));
    return ret;
}

#else
/* code for 32 bit Intel arch */

typedef unsigned int address_t;
#define JB_SP 4
#define JB_PC 5

/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%gs:0x18,%0\n"
                 "rol    $0x9,%0\n"
    : "=g" (ret)
    : "0" (addr));
    return ret;
}

#endif

/**
 * get min from set
 * @param my_set set
 * @return min int
 */
int popMin(set<int> &my_set)
{

    // Get the minimum element
    int min_element;
    if (! my_set.empty())
    {
        min_element = *(-- my_set.rend());
        my_set.erase(min_element);
    } else
    {
        min_element = - 1;
    }
    // return the minimum element
    return min_element;
}

/**
 * handler for SIGVTALR
 * @param sig_num
 */
void
timerHandler(int sig_num); // need to be outside of class
sigset_t signalsSet;   // need to be out of the class because is used in the timeHandler

/**
 * block SIGVTALR timer
 */
void block_timer()
{
    if (sigprocmask(SIG_BLOCK, &signalsSet, NULL) < 0)
    {
        perror(SYS_ERROR);
        exit(1);
    }
}

/**
 * unblock SIGVTALR
 */
void unblock_timer()
{
    if (sigprocmask(SIG_UNBLOCK, &signalsSet, NULL) < 0)
    {
        perror(SYS_ERROR);
        exit(1);
    }
}

/**
 * represent a single thread
 */
class Thread
{
private:
    int tid;
    int tprio;
    int quantumsCounter;
    sigjmp_buf sigjmpBuf;
    char stack[STACK_SIZE];
    bool is_first_time; //indicate if this is the first quantum of thread

public:
    /**
     * constructor for all threads but 0
     * @param tid thread id
     * @param tprio prio for quantum time
     * @param f start point of thread
     */
    Thread(int tid, int tprio, void (*f)(void)) : Thread(tid, tprio)
    {
        this->is_first_time = true;
        this->tid = tid;
        this->tprio = tprio;
        this->quantumsCounter = 0;
        address_t sp = (address_t) this->stack + STACK_SIZE - sizeof(address_t);
        sigsetjmp(this->sigjmpBuf, 1);
        (this->sigjmpBuf->__jmpbuf)[JB_SP] = translate_address(sp);
        (this->sigjmpBuf->__jmpbuf)[JB_PC] = translate_address((address_t) f);

        if (sigemptyset(&(this->sigjmpBuf)->__saved_mask) < 0)
        {
            perror(SYS_ERROR);
            exit(1);
        }
    }

    /**
     * constructor for main thread
     * @param tid thread id
     * @param tprio prio for quantum time
     */
    Thread(int tid, int tprio)
    {
        this->is_first_time = true;
        this->tid = tid;
        this->tprio = tprio;
        this->quantumsCounter = 0;
        address_t sp = (address_t) stack + STACK_SIZE - sizeof(address_t);
        sigsetjmp(this->sigjmpBuf, 1);
        (this->sigjmpBuf->__jmpbuf)[JB_SP] = translate_address(sp);
        if (sigemptyset(&(this->sigjmpBuf)->__saved_mask) < 0)
        {
            perror(SYS_ERROR);
            exit(1);
        };
    }

    void set_first_time_to_false()
    {
        this->is_first_time = false;
    }

    bool get_is_first_time()
    {
        return is_first_time;
    }

    void incrementQuantumsCounter()
    {
        ++ this->quantumsCounter;
    }

    sigjmp_buf &getSigjmpBuf()
    {
        return sigjmpBuf;
    }

    int getQuantumsCounter()
    {
        return this->quantumsCounter;
    }

    void setTprio(const int tprio)
    {
        this->tprio = tprio;
    }

    int getTid() const
    {
        return tid;
    }

    int getTprio() const
    {
        return tprio;
    }
};

class ThreadLibrary
{
private:
    static ThreadLibrary *instance; //singleton
    Thread *currentThread;
    list<Thread *> ready;
    list<Thread *> toDelete; //threads to be deleted
    unordered_set<Thread *> blocked;
    unordered_map<int, Thread *> threadsPool; //pool of all existing threads
    set<int> availableIds;
    int numOfPrios; //max prio -1
    int *quantum_usecs;
    int allTotalQuantums;
    struct sigaction sa;
    struct itimerval timer = {0};

    /**
     * init main thread
     */
    void init_main_thread()
    {
        try
        {
            currentThread = new Thread(0, 0);
        }
        catch (const bad_alloc &e)
        {
            perror(SYS_ERROR);
            exit(1);
        }
        addToThreadPool(currentThread, 0);
        currentThread->incrementQuantumsCounter();
        currentThread->set_first_time_to_false();
        setTimer();
    }

    /**
     * Constructor
     */
    ThreadLibrary(const int *quantum_usecs, int size)
    {
        try
        {
            this->quantum_usecs = new int[size];
        }
        catch (const bad_alloc &e)
        {
            perror(SYS_ERROR);
            exit(1);
        }
        numOfPrios = size;

        for (int i = 1; i < MAX_THREAD_NUM; ++ i)
        {
            availableIds.insert(i);
        }
        for (int i = 0; i < size; ++ i)
        {
            this->quantum_usecs[i] = quantum_usecs[i];
        }
        this->allTotalQuantums = 1;
        if (sigemptyset(&signalsSet) < 0)
        {
            perror(SYS_ERROR);
            exit(1);
        };
        if (sigaddset(&signalsSet, SIGVTALRM) < 0)
        {
            perror(SYS_ERROR);
            exit(1);
        };
        this->sa.sa_handler = &timerHandler;
        if (sigaction(SIGVTALRM, &sa, NULL) < 0)
        {
            perror(SYS_ERROR);
            exit(1);
        }
        init_main_thread();
    }

    /**
     * delete all threads object in toDelete
     */
    void delete_waiting_threads()
    {
        if (! this->toDelete.empty())
        {
            for (Thread *thread : this->toDelete)
            {
                delete thread; //no need for catch exception, noexcept method
            }
            toDelete.clear();
        }
    }

    /**
     * activate virtual timer in according to the current thread prio -> quantum
     */
    void setTimer()
    {
        int tprio = this->currentThread->getTprio();
        timer.it_value.tv_sec = quantum_usecs[tprio] / SECOND;
        timer.it_value.tv_usec = quantum_usecs[tprio] % SECOND;

        if (setitimer(ITIMER_VIRTUAL, &timer, NULL))
        {
            perror(SYS_ERROR);
            exit(1);
        }
        unblock_timer();
    }

    /**
     * increment the total lib quantum counter and the thread quantum counter
     */
    void incrementQuantomCounters()
    {
        ++ allTotalQuantums;
        currentThread->incrementQuantumsCounter();
    }

public:
    /**
     * singleton instance getter
     * @param quantum_usecs
     * @param size
     * @return lib instance
     */
    static ThreadLibrary *getInstance(const int *quantum_usecs, int size)
    //singleton
    {
        if (instance == nullptr)
        {
            try
            {
                instance = new ThreadLibrary(quantum_usecs, size);
            }
            catch (const bad_alloc &e)
            {
                perror(SYS_ERROR);
                exit(1);
            }
        }
        return instance;
    }

    /**
     * destructor
     */
    ~ThreadLibrary()
    {
        delete[] quantum_usecs;
        for (int i = 0; i < MAX_THREAD_NUM; i ++)
        {
            if (isThreadExists(i))
            {
                delete_thread(i);
            }
        }
        this->delete_waiting_threads();
    }

    /**
     * in charge of switch between threads (when timer ends, thread is blocked or terminated)
     * according to Robin algorithm
     */
    void switchThreads(bool flagTerminate, bool flagBlocked)
    {
        int ret_val = 0;
        if (! flagTerminate)
        {
            ret_val = sigsetjmp(currentThread->getSigjmpBuf(), 1);
        }
        if (ret_val ==
            1) // begining of new quantum run, thread that is terminating will never enter here
        {
            this->delete_waiting_threads();
            this->incrementQuantomCounters();
            setTimer();
            return;
        }
        if (! flagBlocked && ! flagTerminate)
        {
            addThreadToReady(currentThread);
        }
        currentThread = getNextThread();
        /**
         * in threads first time they wont enter the above section - lines 390-393
         */
        if (currentThread->get_is_first_time())
        {
            currentThread->set_first_time_to_false();
            this->incrementQuantomCounters();
            setTimer();
        }
        siglongjmp(currentThread->getSigjmpBuf(), 1);
    }

    /**
     * perform all actions needed to clear thread from memory
     * @param tid
     */
    void delete_thread(int tid)
    {
        availableIds.insert(tid);
        Thread *threadToDelete = threadsPool[tid];
        threadsPool.erase(tid);
        if (isThreadBlocked(threadToDelete))
        {
            removeThreadFromBlocked(threadToDelete);
        }
        removeFromReady(threadToDelete);
        toDelete.push_back(threadToDelete);
    }

    int getNumOfPrios() const
    {
        return numOfPrios;
    }

    Thread *getThread(int tid)
    {
        return threadsPool[tid];
    }

    /**
     * check if certain tid represent exist thread
     * @param tid
     * @return bool
     */
    bool isThreadExists(int tid)
    {

        if (0 <= tid && tid < MAX_THREAD_NUM)
        {
            return 0 == this->availableIds.count(tid);
        }
        return false;
    }

    /**
     * add thread to data structure
     */
    void addToThreadPool(Thread *thread, int tid)
    {
        threadsPool[tid] = thread;
    }

    int getAllTotalQuantums()
    {
        return this->allTotalQuantums;
    }

    /**
     * get the current running thread
     * @return
     */
    Thread *getCurrentThread()
    {
        return currentThread;
    }

    /**
     * remove thread from READY line
     * @param thread
     */
    void removeFromReady(Thread *thread)
    {
        ready.remove(thread);
    }

    /**
     * get the next minimal available id
     * @return
     */
    int getAvailableId()
    {
        if (availableIds.empty())
        {
            cerr << MAX_THREAD_ERR << endl;
            return - 1;
        }
        return popMin(availableIds);
    }

    /**
     * add thread to end of READY line
     * @param thread
     */
    void addThreadToReady(Thread *thread)
    {
        ready.push_back(thread);
    }

    bool isThreadBlocked(Thread *thread)
    {
        return 1 == blocked.count(thread);
    }

    /**
     * retrieve the next thread in READY line
     * @return
     */
    Thread *getNextThread()
    {
        Thread *thread = ready.front();
        ready.pop_front();
        return thread;
    }

    void addThreadToBlocked(Thread *thread)
    {
        blocked.insert(thread);
    }

    void removeThreadFromBlocked(Thread *thread)
    {
        blocked.erase(thread);
    }

};

ThreadLibrary *ThreadLibrary::instance = 0;
ThreadLibrary *tlib;

void timerHandler(int sig_num)
{
    block_timer();
    tlib->switchThreads(false, false);
}

int uthread_init(int *quantum_usecs, int size)
{
    if (size <= 0)
    {
        cerr << SIZE_ERR << endl;
        return - 1;
    }
    for (int i = 0; i < size; ++ i)
    {
        if (quantum_usecs[i] <= 0)
        {
            cerr << NEG_TIME_ERR << endl;
            return - 1;
        }
    }
    tlib = tlib->getInstance(quantum_usecs, size);
    return 0;
}

int uthread_spawn(void (*f)(void), int priority)
{
    block_timer();
    if (priority >= tlib->getNumOfPrios() || priority < 0)
    {
        cerr << NO_SUCH_PRIO_ERR << endl;
        return - 1;
    }
    int tid = tlib->getAvailableId();
    if (tid == - 1)
    {
        return - 1;
    }

    Thread *newThread;

    try
    {
        newThread = new Thread(tid, priority, f);
    }
    catch (const bad_alloc &e)
    {
        perror(SYS_ERROR);
        exit(1);
    }
    tlib->addThreadToReady(newThread);
    tlib->addToThreadPool(newThread, tid);
    unblock_timer();
    return tid;
}

int uthread_change_priority(int tid, int priority)
{
    block_timer();
    if (! tlib->isThreadExists(tid))
    {
        cerr << NO_SUCH_THREAD_ERR << endl;
        return - 1;
    }
    if (priority >= tlib->getNumOfPrios() || priority < 0)
    {
        cerr << NO_SUCH_PRIO_ERR << endl;
        return - 1;
    }
    tlib->getThread(tid)->setTprio(priority);
    unblock_timer();
    return 0;
}

int uthread_terminate(int tid)
{
    block_timer();

    if (! tlib->isThreadExists(tid))
    {
        cerr << NO_SUCH_THREAD_ERR << endl;
        return - 1;
    }

    if (tid == 0)
    {
        delete tlib;
        exit(0);
    }

    tlib->delete_thread(tid);

    if (uthread_get_tid() == tid)
    {
        tlib->switchThreads(true, false);
    }
    unblock_timer();
    return 0;
}

int uthread_block(int tid)
{
    block_timer();
    if (! tlib->isThreadExists(tid))
    {
        cerr << NO_SUCH_THREAD_ERR << endl;
        return - 1;
    }
    if (tid == 0)
    {
        cerr << MAIN_BLOCK_ERR << endl;
        return - 1;
    }
    Thread *thread = tlib->getThread(tid);
    tlib->addThreadToBlocked(thread);
    tlib->removeFromReady(thread);
    if (uthread_get_tid() == tid) // current tid
    {
        tlib->switchThreads(false, true);
    }
    unblock_timer();
    return 0;

}

int uthread_resume(int tid)
{
    block_timer();
    if (! tlib->isThreadExists(tid))
    {
        cerr << NO_SUCH_THREAD_ERR << endl;
        return - 1;
    }
    Thread *thread = tlib->getThread(tid);
    if (tlib->isThreadBlocked(thread))
    {
        tlib->addThreadToReady(thread);
        tlib->removeThreadFromBlocked(thread);
    }
    unblock_timer();
    return 0;
}

int uthread_get_tid()
{

    return tlib->getCurrentThread()->getTid();
}

int uthread_get_total_quantums()
{
    return tlib->getAllTotalQuantums();
}

int uthread_get_quantums(int tid)
{
    if (! tlib->isThreadExists(tid))
    {
        cerr << NO_SUCH_THREAD_ERR << endl;
        return - 1;
    }
    return tlib->getThread(tid)->getQuantumsCounter();
}