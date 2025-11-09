"""Background task scheduler for periodic report generation"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .generator import ReportGenerator
from .models import ReportLevel, ReportFrequency, ReportConfiguration

logger = structlog.get_logger()


class ReportScheduler:
    """Manages periodic report generation using APScheduler"""
    
    def __init__(self, report_generator: ReportGenerator, 
                 config: Optional[ReportConfiguration] = None):
        self.report_generator = report_generator
        self.config = config or ReportConfiguration()
        self.scheduler = AsyncIOScheduler()
        self._jobs: Dict[str, str] = {}  # job_id -> description mapping
    
    async def start(self):
        """Start the report scheduler"""
        if not self.config.enabled:
            logger.info("Report scheduling is disabled")
            return
        
        logger.info("Starting report scheduler...")
        
        # Schedule reports based on configuration
        await self._schedule_reports()
        
        # Start the scheduler
        self.scheduler.start()
        logger.info("Report scheduler started successfully")
    
    async def stop(self):
        """Stop the report scheduler"""
        logger.info("Stopping report scheduler...")
        self.scheduler.shutdown(wait=True)
        logger.info("Report scheduler stopped")
    
    async def _schedule_reports(self):
        """Schedule all configured reports"""
        
        for level in self.config.levels:
            frequency = self.config.frequencies.get(level, ReportFrequency.DAILY)
            await self._schedule_report_level(level, frequency)
        
        # Schedule cleanup task
        self.scheduler.add_job(
            self._cleanup_old_reports,
            trigger=CronTrigger(hour=2, minute=0),  # Daily at 2 AM
            id="cleanup_reports",
            name="Cleanup old reports",
            misfire_grace_time=3600
        )
        self._jobs["cleanup_reports"] = "Daily cleanup of old reports"
    
    async def _schedule_report_level(self, level: ReportLevel, frequency: ReportFrequency):
        """Schedule reports for a specific level and frequency"""
        
        job_id = f"report_{level.value}_{frequency.value}"
        job_name = f"{level.value.title()} Report ({frequency.value})"
        
        if frequency == ReportFrequency.REAL_TIME:
            # Real-time alerts are event-driven, not scheduled
            logger.info(f"Skipping scheduler for real-time alerts ({level.value})")
            return
        
        elif frequency == ReportFrequency.HOURLY:
            trigger = IntervalTrigger(hours=1)
            period_hours = 1
            
        elif frequency == ReportFrequency.DAILY:
            # Stagger reports with higher frequency for better monitoring
            if level == ReportLevel.EXECUTIVE:
                # Executive reports every 4 hours at :30 (0:30, 4:30, 8:30, 12:30, 16:30, 20:30)
                trigger = CronTrigger(hour='*/4', minute=30)
                period_hours = 4
            elif level == ReportLevel.TECHNICAL:
                # Technical reports every 6 hours at :45 (0:45, 6:45, 12:45, 18:45)
                trigger = CronTrigger(hour='*/6', minute=45)
                period_hours = 6
            elif level == ReportLevel.DETAILED:
                # Detailed reports once daily at 10 PM
                trigger = CronTrigger(hour=22, minute=0)
                period_hours = 24
            else:
                # Default: every 8 hours for other levels
                trigger = IntervalTrigger(hours=8)
                period_hours = 24
            
        elif frequency == ReportFrequency.WEEKLY:
            trigger = CronTrigger(day_of_week='mon', hour=8, minute=0)  # Weekly on Monday
            period_hours = 168  # 7 days
            
        elif frequency == ReportFrequency.MONTHLY:
            trigger = CronTrigger(day=1, hour=8, minute=0)  # Monthly on 1st
            period_hours = 720  # 30 days
            
        else:
            logger.warning(f"Unsupported frequency: {frequency}")
            return
        
        # Add the scheduled job
        self.scheduler.add_job(
            self._generate_scheduled_report,
            trigger=trigger,
            args=[level, period_hours],
            id=job_id,
            name=job_name,
            misfire_grace_time=3600,  # 1 hour grace period
            max_instances=1  # Prevent overlapping executions
        )
        
        self._jobs[job_id] = job_name
        logger.info(f"Scheduled {job_name} with trigger: {trigger}")
    
    async def _generate_scheduled_report(self, level: ReportLevel, period_hours: int):
        """Generate a scheduled report"""
        try:
            logger.info(f"Generating scheduled {level.value} report for {period_hours}h period")
            
            report = await self.report_generator.generate_report(
                level=level,
                period_hours=period_hours,
                focus_areas=None
            )
            
            logger.info(f"Successfully generated scheduled report: {report.metadata.id}")
            
            # Trigger real-time alert if critical issues detected
            if level == ReportLevel.EXECUTIVE and hasattr(report, 'executive_summary'):
                if report.executive_summary and report.executive_summary.threat_level == "CRITICAL":
                    await self._trigger_critical_alert(report)
            
        except Exception as e:
            logger.error(f"Failed to generate scheduled {level.value} report: {e}")
    
    async def _trigger_critical_alert(self, report):
        """Trigger immediate alert for critical security issues"""
        try:
            alert_report = await self.report_generator.generate_report(
                level=ReportLevel.REAL_TIME,
                period_hours=1,
                focus_areas=["critical_alert"]
            )
            logger.warning(f"Critical security alert generated: {alert_report.metadata.id}")
            
        except Exception as e:
            logger.error(f"Failed to generate critical alert: {e}")
    
    async def _cleanup_old_reports(self):
        """Clean up old reports based on retention policy"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.config.retention_days)
            logger.info(f"Cleaning up reports older than {cutoff_date}")
            
            # This would implement actual cleanup logic
            # For now, just log the action
            logger.info(f"Cleanup completed - retention policy: {self.config.retention_days} days")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old reports: {e}")
    
    def get_scheduled_jobs(self) -> Dict[str, Dict]:
        """Get information about scheduled jobs"""
        jobs = {}
        for job in self.scheduler.get_jobs():
            jobs[job.id] = {
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
                "description": self._jobs.get(job.id, "Unknown job")
            }
        return jobs
    
    async def _generate_kubernetes_health_report(self):
        """Generate scheduled Kubernetes cluster health report"""
        try:
            logger.info("Generating scheduled Kubernetes cluster health report")
            
            report = await self.report_generator.generate_report(
                level=ReportLevel.EXECUTIVE,
                period_hours=24,
                focus_areas=["kubernetes", "cluster_health", "error_analysis"]
            )
            
            logger.info(f"Successfully generated Kubernetes health report: {report.metadata.id}")
            
        except Exception as e:
            logger.error(f"Failed to generate Kubernetes health report: {e}")
    
    async def _generate_network_security_report(self):
        """Generate scheduled network security report"""
        try:
            logger.info("Generating scheduled network security report")
            
            report = await self.report_generator.generate_report(
                level=ReportLevel.EXECUTIVE,
                period_hours=24,
                focus_areas=["network_security", "zeek_analysis", "threat_detection"]
            )
            
            logger.info(f"Successfully generated network security report: {report.metadata.id}")
            
        except Exception as e:
            logger.error(f"Failed to generate network security report: {e}")
    
    async def trigger_manual_report(self, level: ReportLevel, period_hours: int = 24) -> str:
        """Manually trigger report generation"""
        logger.info(f"Manually triggering {level.value} report")
        
        report = await self.report_generator.generate_report(
            level=level,
            period_hours=period_hours
        )
        
        return report.metadata.id
    
    def is_running(self) -> bool:
        """Check if scheduler is running"""
        return self.scheduler.running