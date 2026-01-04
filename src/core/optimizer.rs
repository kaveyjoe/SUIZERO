// src/core/optimizer.rs
use crate::types::{DetectionContext, SecurityIssue};
use crate::core::detector::SecurityDetector;
use rayon::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;

pub struct ParallelDetectionEngine {
    detectors: Arc<Vec<Box<dyn SecurityDetector>>>,
    cache: DashMap<String, Vec<SecurityIssue>>,
    work_stealing: bool,
    batch_size: usize,
}

impl ParallelDetectionEngine {
    pub fn new(detectors: Vec<Box<dyn SecurityDetector>>) -> Self {
        Self {
            detectors: Arc::new(detectors),
            cache: DashMap::new(),
            work_stealing: true,
            batch_size: 10,
        }
    }
    
    pub async fn analyze(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let cache_key = format!("{:?}", ctx.module.self_id());
        
        if let Some(cached) = self.cache.get(&cache_key) {
            return cached.clone();
        }
        
        let detectors_by_category = self.group_detectors_by_category();
        
        let issues: Vec<Vec<SecurityIssue>> = detectors_by_category
            .par_iter()
            .with_min_len(self.batch_size)
            .map(|category_detectors| {
                let mut category_issues = Vec::new();
                
                for detector in category_detectors {
                    if detector.should_run(ctx) {
                        let detector_issues = tokio::task::block_in_place(|| {
                            futures::executor::block_on(detector.detect(ctx))
                        });
                        category_issues.extend(detector_issues);
                    }
                }
                
                category_issues
            })
            .collect();
        
        let all_issues: Vec<SecurityIssue> = issues.into_iter().flatten().collect();
        
        self.cache.insert(cache_key, all_issues.clone());
        
        all_issues
    }
    
    fn group_detectors_by_category(&self) -> Vec<Vec<&Box<dyn SecurityDetector>>> {
        let mut categories = std::collections::HashMap::new();
        
        for detector in self.detectors.iter() {
            let category = detector.id().split('-').next().unwrap_or("unknown");
            categories.entry(category)
                .or_insert_with(Vec::new)
                .push(detector);
        }
        
        categories.into_values().collect()
    }
}