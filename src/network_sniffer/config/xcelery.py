from celery import Celery


app = Celery('lchtools', broker='redis://redis:6379/0')
app.conf.update(
    task_serializer='json',
    result_backend='redis://redis:6379/0',
    broker_connection_retry_on_startup=True,
    include=['network_sniffer.tasks']
)