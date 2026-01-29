#!/usr/bin/env python3
"""
Анализатор Kubernetes Audit Log для выявления подозрительных событий
"""

import json
import sys
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional


class KubernetesAuditAnalyzer:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.events = []
        self.suspicious_events = {
            'secret_access': [],
            'privileged_pods': [],
            'exec_in_pods': [],
            'admin_rolebindings': [],
            'audit_policy_deletion': []
        }
        
    def load_logs(self):
        """Загрузка логов из файла"""
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line.strip())
                            self.events.append(event)
                        except json.JSONDecodeError:
                            print(f"Warning: Не удалось распарсить строку: {line[:100]}...")
        except FileNotFoundError:
            print(f"Ошибка: Файл {self.log_file_path} не найден")
            sys.exit(1)
            
    def analyze_secret_access(self):
        """Анализ доступа к секретам"""
        suspicious_users = set()
        
        for event in self.events:
            # Проверяем доступ к секретам
            if (event.get('objectRef', {}).get('resource') == 'secrets' and
                event.get('verb') in ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']):
                
                user = event.get('user', {})
                username = user.get('username', 'unknown')
                
                # Игнорируем системные аккаунты (если нужно)
                if username.startswith('system:'):
                    continue
                    
                # Проверяем подозрительные паттерны
                is_suspicious = False
                reasons = []
                
                # Доступ к секретам в разных неймспейсах
                if event.get('objectRef', {}).get('namespace') not in [None, 'default', 'kube-system']:
                    reasons.append(f"доступ к секретам в неймспейсе {event['objectRef'].get('namespace')}")
                
                # Множественные запросы к секретам
                if event.get('verb') in ['list', 'watch']:
                    reasons.append("перечисление секретов")
                
                # Удаление секретов
                if event.get('verb') == 'delete':
                    reasons.append("удаление секретов")
                
                if reasons:
                    suspicious_users.add(username)
                    self.suspicious_events['secret_access'].append({
                        'user': username,
                        'timestamp': event.get('requestReceivedTimestamp'),
                        'action': event.get('verb'),
                        'resource': event.get('objectRef', {}).get('name', 'unknown'),
                        'namespace': event.get('objectRef', {}).get('namespace'),
                        'source_ip': event.get('sourceIPs', ['unknown'])[0],
                        'reasons': reasons
                    })
    
    def analyze_privileged_pods(self):
        """Анализ привилегированных подов"""
        for event in self.events:
            if (event.get('objectRef', {}).get('resource') == 'pods' and
                event.get('verb') in ['create', 'update', 'patch']):
                
                # Ищем спецификацию пода с привилегированными настройками
                request_object = event.get('requestObject', {})
                spec = request_object.get('spec', {})
                
                # Проверяем securityContext
                security_context = {}
                if spec.get('containers'):
                    for container in spec['containers']:
                        if container.get('securityContext'):
                            security_context = container['securityContext']
                            break
                elif spec.get('securityContext'):
                    security_context = spec['securityContext']
                
                # Проверяем привилегированные флаги
                privileged_flags = []
                if security_context.get('privileged') is True:
                    privileged_flags.append('privileged=true')
                if security_context.get('allowPrivilegeEscalation') is True:
                    privileged_flags.append('allowPrivilegeEscalation=true')
                if security_context.get('runAsUser') == 0:
                    privileged_flags.append('runAsUser=0 (root)')
                
                # Проверяем hostPath volumes
                volumes = spec.get('volumes', [])
                for volume in volumes:
                    if volume.get('hostPath'):
                        privileged_flags.append(f"hostPath volume: {volume['hostPath'].get('path')}")
                
                if privileged_flags:
                    self.suspicious_events['privileged_pods'].append({
                        'user': event.get('user', {}).get('username', 'unknown'),
                        'timestamp': event.get('requestReceivedTimestamp'),
                        'pod_name': event.get('objectRef', {}).get('name'),
                        'namespace': event.get('objectRef', {}).get('namespace'),
                        'privileged_flags': privileged_flags
                    })
    
    def analyze_exec_in_pods(self):
        """Анализ использования kubectl exec"""
        for event in self.events:
            # Проверяем запросы exec к подам
            if ('pods/exec' in event.get('requestURI', '') or 
                (event.get('objectRef', {}).get('subresource') == 'exec' and
                 event.get('objectRef', {}).get('resource') == 'pods')):
                
                user = event.get('user', {})
                username = user.get('username', 'unknown')
                
                # Игнорируем системные аккаунты
                if not username.startswith('system:'):
                    self.suspicious_events['exec_in_pods'].append({
                        'user': username,
                        'timestamp': event.get('requestReceivedTimestamp'),
                        'pod': event.get('objectRef', {}).get('name'),
                        'namespace': event.get('objectRef', {}).get('namespace'),
                        'command': event.get('requestObject', {}).get('command', ['unknown']),
                        'source_ip': event.get('sourceIPs', ['unknown'])[0]
                    })
    
    def analyze_admin_rolebindings(self):
        """Анализ создания RoleBinding с правами cluster-admin"""
        for event in self.events:
            if (event.get('objectRef', {}).get('resource') in ['rolebindings', 'clusterrolebindings'] and
                event.get('verb') in ['create', 'update', 'patch']):
                
                request_object = event.get('requestObject', {})
                role_ref = request_object.get('roleRef', {})
                
                # Проверяем, ссылается ли на cluster-admin
                if (role_ref.get('name') == 'cluster-admin' or 
                    role_ref.get('name') == 'admin'):
                    
                    self.suspicious_events['admin_rolebindings'].append({
                        'user': event.get('user', {}).get('username', 'unknown'),
                        'timestamp': event.get('requestReceivedTimestamp'),
                        'binding_name': event.get('objectRef', {}).get('name'),
                        'namespace': event.get('objectRef', {}).get('namespace'),
                        'role': role_ref.get('name'),
                        'subjects': request_object.get('subjects', [])
                    })
    
    def analyze_audit_policy_deletion(self):
        """Анализ удаления audit-policy"""
        for event in self.events:
            if (event.get('objectRef', {}).get('resource') == 'configmaps' and
                event.get('verb') == 'delete'):
                
                configmap_name = event.get('objectRef', {}).get('name', '').lower()
                if 'audit' in configmap_name and 'policy' in configmap_name:
                    self.suspicious_events['audit_policy_deletion'].append({
                        'user': event.get('user', {}).get('username', 'unknown'),
                        'timestamp': event.get('requestReceivedTimestamp'),
                        'configmap': event.get('objectRef', {}).get('name'),
                        'namespace': event.get('objectRef', {}).get('namespace'),
                        'source_ip': event.get('sourceIPs', ['unknown'])[0]
                    })
    
    def generate_report(self) -> str:
        """Генерация отчёта"""
        report = []
        report.append("# Отчёт по результатам анализа Kubernetes Audit Log")
        report.append(f"## Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"## Всего событий: {len(self.events)}")
        report.append("")
        
        # Подозрительные события
        report.append("## Подозрительные события")
        report.append("")
        
        # 1. Доступ к секретам
        report.append("1. Доступ к секретам:")
        if self.suspicious_events['secret_access']:
            for event in self.suspicious_events['secret_access'][:10]:  # Ограничиваем вывод
                report.append(f"   - Кто: {event['user']}")
                report.append(f"   - Где: неймспейс {event['namespace']}, ресурс {event['resource']}")
                report.append(f"   - Почему подозрительно: {'; '.join(event['reasons'])}")
                report.append(f"   - Время: {event['timestamp']}")
                report.append(f"   - Источник: {event['source_ip']}")
                report.append("")
        else:
            report.append("   - Подозрительных событий не обнаружено")
            report.append("")
        
        # 2. Привилегированные поды
        report.append("2. Привилегированные поды:")
        if self.suspicious_events['privileged_pods']:
            for event in self.suspicious_events['privileged_pods'][:10]:
                report.append(f"   - Кто: {event['user']}")
                report.append(f"   - Под: {event['pod_name']} в неймспейсе {event['namespace']}")
                report.append(f"   - Комментарий: {', '.join(event['privileged_flags'])}")
                report.append("")
        else:
            report.append("   - Подозрительных событий не обнаружено")
            report.append("")
        
        # 3. Использование kubectl exec в чужом поде
        report.append("3. Использование kubectl exec в подах:")
        if self.suspicious_events['exec_in_pods']:
            for event in self.suspicious_events['exec_in_pods'][:10]:
                report.append(f"   - Кто: {event['user']}")
                report.append(f"   - Что делал: exec в под {event['pod']} (команда: {' '.join(event['command'])})")
                report.append(f"   - Неймспейс: {event['namespace']}")
                report.append("")
        else:
            report.append("   - Подозрительных событий не обнаружено")
            report.append("")
        
        # 4. Создание RoleBinding с правами cluster-admin
        report.append("4. Создание RoleBinding с правами cluster-admin:")
        if self.suspicious_events['admin_rolebindings']:
            for event in self.suspicious_events['admin_rolebindings']:
                report.append(f"   - Кто: {event['user']}")
                report.append(f"   - К чему привело: создан {event['binding_name']} с ролью {event['role']}")
                report.append(f"   - Субъекты: {json.dumps(event['subjects'], ensure_ascii=False)}")
                report.append("")
        else:
            report.append("   - Подозрительных событий не обнаружено")
            report.append("")
        
        # 5. Удаление audit-policy.yaml
        report.append("5. Удаление audit-policy:")
        if self.suspicious_events['audit_policy_deletion']:
            for event in self.suspicious_events['audit_policy_deletion']:
                report.append(f"   - Кто: {event['user']}")
                report.append(f"   - Возможные последствия: отключение аудита, сложность расследования инцидентов")
                report.append(f"   - Удалённый ресурс: {event['configmap']}")
                report.append("")
        else:
            report.append("   - Подозрительных событий не обнаружено")
            report.append("")
        
        # Вывод
        report.append("## Вывод")
        
        total_suspicious = sum(len(events) for events in self.suspicious_events.values())
        
        if total_suspicious == 0:
            report.append("Подозрительных событий не обнаружено. Кластер работает в нормальном режиме.")
        else:
            report.append(f"Обнаружено {total_suspicious} подозрительных событий:")
            for category, events in self.suspicious_events.items():
                if events:
                    category_name = {
                        'secret_access': 'доступ к секретам',
                        'privileged_pods': 'привилегированные поды',
                        'exec_in_pods': 'exec в подах',
                        'admin_rolebindings': 'роли администратора',
                        'audit_policy_deletion': 'удаление политик аудита'
                    }.get(category, category)
                    report.append(f"  - {category_name}: {len(events)} событий")
            
            report.append("\nРекомендации:")
            report.append("1. Провести детальный анализ событий, отмеченных как подозрительные")
            report.append("2. Проверить настройки RBAC и ограничить привилегии пользователей")
            report.append("3. Убедиться, что политика аудита не была скомпрометирована")
            report.append("4. Проверить поды с привилегированным доступом на соответствие политикам безопасности")
        
        return "\n".join(report)
    
    def analyze(self):
        """Запуск полного анализа"""
        print("Загрузка логов...")
        self.load_logs()
        
        print("Анализ доступа к секретам...")
        self.analyze_secret_access()
        
        print("Анализ привилегированных подов...")
        self.analyze_privileged_pods()
        
        print("Анализ использования kubectl exec...")
        self.analyze_exec_in_pods()
        
        print("Анализ создания RoleBinding...")
        self.analyze_admin_rolebindings()
        
        print("Анализ удаления политик аудита...")
        self.analyze_audit_policy_deletion()
        
        print("Генерация отчёта...")
        return self.generate_report()


def main():
    if len(sys.argv) != 2:
        print("Использование: python audit_analyzer.py <путь_к_файлу_логов>")
        print("Пример: python audit_analyzer.py /var/log/kubernetes/audit.log")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    analyzer = KubernetesAuditAnalyzer(log_file)
    report = analyzer.analyze()
    
    # Сохраняем отчёт в файл
    output_file = f"analysis-{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(report)
    print(f"\nОтчёт сохранён в файл: {output_file}")


if __name__ == "__main__":
    main()