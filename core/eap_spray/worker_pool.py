import core.eap_spray

class Worker_Pool(object):

    def __init__(self, interfaces, essid, password, input_queue, output_queue, conf_dir):

        self.workers = []
        for index,interface in enumerate(interfaces):
            worker = core.eap_spray.Worker(
                                        interface,
                                        essid,
                                        password,
                                        input_queue,
                                        output_queue,
                                        conf_dir,
            )
            self.workers.append(worker)

    def start(self):

        for worker in self.workers:
            worker.start()

    def join(self):

        for worker in self.workers:
            worker.join()
