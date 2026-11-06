"""Expose imported UI history while keeping current coursework state independent."""
from posture.orchestration import PostureAssessmentOrchestrator


class CourseworkPosture(PostureAssessmentOrchestrator):
    def __init__(self, project, catalog):
        super().__init__(project, catalog, state_relative='runtime/coursework/posture')
        self.archive = PostureAssessmentOrchestrator(project, catalog)
        from coursework.lab import available,credentials
        if available():
            from posture.providers import ZapAPI
            origin,key=credentials()
            self.providers['zap'].api=ZapAPI(origin,key)
            self.providers['zap'].owned_ephemeral=True

    def location(self, aid):
        current = super().location(aid)
        historical = self.archive.location(aid)
        return historical if not current.exists() and historical.exists() else current

    def get(self, aid):
        value = super().get(aid)
        if self.location(aid).is_relative_to(self.archive.root):
            value = dict(value, coursework_origin='IMPORTED_HISTORICAL_ONLY', counted_as_current=False)
        return value

    def history(self):
        current = super().history()
        imported = [self.get(j['assessment_id']) for j in self.archive.history()]
        known = {j['assessment_id'] for j in current}
        return sorted(current + [j for j in imported if j['assessment_id'] not in known],
                      key=lambda j: (j['started_at'], j['assessment_id']), reverse=True)

    def latest(self, successful=False):
        # Explicit history selection works, but never adopt imported latest jobs.
        return next((j for j in super().history()
                     if not successful or j['status'] in ('COMPLETE', 'PARTIAL')), None)

    def last_successful_zap(self):
        return next((j for j in super().history()
                     if j.get('provider_statuses', {}).get('zap') == 'COMPLETE'), None)
