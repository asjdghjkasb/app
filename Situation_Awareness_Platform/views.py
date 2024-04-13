from django.contrib import messages
from django.http import HttpRequest, JsonResponse
from django.shortcuts import redirect, render
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from .models import AttackEvent, Apache
from datetime import datetime, timedelta
import secrets
from django.db.models import Count
from django.conf import settings


def token_valid(request):
    if isinstance(request, HttpRequest):
        if 'token_expiry' in request.session:
            expiry_time_str = request.session['token_expiry']
            expiry_time = datetime.strptime(expiry_time_str, '%Y-%m-%d %H:%M:%S')
            if expiry_time > datetime.now():
                return True
    return False


@login_required
def dashboard(request):
    if token_valid(request):
        attack_events = AttackEvent.objects.all()
        context = {'attack_events': attack_events}
        return render(request, 'dashboard.html', context)
    else:
        return redirect('login')


def generate_token(length=32):
    return secrets.token_hex(length)


def index(request):
    return render(request, 'login.html')


def login_view(request):
    login_attempted = request.method == 'POST'  # 检查用户是否尝试了登录
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                request.session['token'] = generate_token()
                request.session['token_expiry'] = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
                return redirect('dashboard')  # 重定向到 dashboard 视图函数
            else:
                return render(request, 'login.html', {'form': form, 'login_attempted': login_attempted, 'login_success': False})
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form, 'login_attempted': login_attempted})

def log_analysis(request):
    # 使用 Django ORM 查询代替系统命令执行
    counts = Apache.objects.values('ip').annotate(count=Count('ip'))
    results = []

    for entry in counts:
        addr = entry['ip']
        count = entry['count']

        if count > settings.burst_num:
            # 取最后30次访问的时间，判断是否是短时间内连续访问
            latest_logs = Apache.objects.filter(ip=addr).order_by('-time')[:30]
            times = [log.time for log in latest_logs]
            stime_h = times[0].hour
            stime_m = times[0].minute
            etime_h = times[-1].hour
            etime_m = times[-1].minute

            if etime_h == stime_h and etime_m - stime_m < 2:
                # 如果是请求的都是同一文件则判断为暴力破解,类型为105
                files = [log.raw_request for log in latest_logs]
                if all(files[i] == files[i+1] for i in range(len(files)-1)):
                    attack_type = 105
                else:
                    attack_type = 103

                results.append({
                    'ip': addr,
                    'num': count,
                    'time': times[0],
                    'attack_type': attack_type,
                    'raw_request': files[-1]
                })
        else:
            latest_logs = Apache.objects.filter(ip=addr).order_by('-time')[:30]
            files = [log.raw_request for log in latest_logs]
            for f in files:
                attack_type = None
                for rule in settings.sqlrule:
                    if rule in f:
                        attack_type = 102
                        break
                for rule in settings.xssrule:
                    if rule in f:
                        attack_type = 101
                        break
                for rule in settings.backrule:
                    if rule in f:
                        attack_type = 106
                        break

                if attack_type is not None:
                    results.append({
                        'ip': addr,
                        'num': count,
                        'time': latest_logs[0].time,
                        'attack_type': attack_type,
                        'raw_request': f
                    })

    # 存入数据库
    for result in results:
        Apache.objects.create(
            ip=result['ip'],
            num=result['num'],
            time=result['time'],
            attack_type=result['attack_type'],
            raw_request=result['raw_request']
        )

    # 将结果传递到 HTML 模板中并渲染
    return render(request, 'log_analysis.html', {'results': results})

def log_view(request):
    return

def defense(request):
    return