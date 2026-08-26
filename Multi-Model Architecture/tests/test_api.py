"""
SentinelAI - FastAPI Backend Endpoint Test Suite
Validates RESTful endpoints, flow ingestion, incident queries, manual unblocking,
and report generation using httpx AsyncClient.
"""

import os
import sys
import asyncio
import unittest
import httpx
from httpx import ASGITransport

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.server import app, lifespan


class TestFastAPIBackend(unittest.TestCase):
    """Integration tests for SentinelAI FastAPI backend."""

    def setUp(self):
        self.transport = ASGITransport(app=app)

    def _run_async(self, coro):
        return asyncio.run(coro)

    def test_root_endpoint(self):
        async def _test():
            async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                resp = await client.get("/")
                self.assertEqual(resp.status_code, 200)
                data = resp.json()
                self.assertEqual(data["system"], "SentinelAI Multi-Agent SOAR Platform")
                self.assertEqual(data["status"], "ONLINE")

        self._run_async(_test())

    def test_system_status_endpoint(self):
        async def _test():
            async with lifespan(app):
                async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                    resp = await client.get("/api/status")
                    self.assertEqual(resp.status_code, 200)
                    data = resp.json()
                    self.assertIn("agent_statuses", data)
                    self.assertIn("cpu_percent", data)
                    self.assertIn("DetectionAgent", data["agent_statuses"])

        self._run_async(_test())

    def test_metrics_kpi_endpoint(self):
        async def _test():
            async with lifespan(app):
                async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                    resp = await client.get("/api/metrics")
                    self.assertEqual(resp.status_code, 200)
                    data = resp.json()
                    self.assertIn("total_flows_analyzed", data)
                    self.assertIn("total_threats_detected", data)
                    self.assertIn("active_firewall_blocks", data)
                    self.assertIn("attack_distribution", data)

        self._run_async(_test())

    def test_flow_ingest_and_incident_query(self):
        async def _test():
            async with lifespan(app):
                async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                    # 1. Ingest PortScan Flow via HTTP POST
                    flow_payload = {
                        "src_ip": "192.168.1.77",
                        "dst_ip": "192.168.1.10",
                        "src_port": 50123,
                        "dst_port": 80,
                        "protocol": 6,
                        "flow_duration": 0.1,
                        "tot_fwd_pkts": 5,
                        "tot_bwd_pkts": 0,
                        "fwd_pkt_len_mean": 20.0,
                        "bwd_pkt_len_mean": 0.0,
                        "flow_bytes_s": 3500.0,
                        "flow_pkts_s": 220.0,
                        "syn_flag_count": 5,
                        "ack_flag_count": 0,
                        "rst_flag_count": 0
                    }
                    resp_ingest = await client.post("/api/flows/ingest", json=flow_payload)
                    self.assertEqual(resp_ingest.status_code, 200)
                    ingest_data = resp_ingest.json()
                    self.assertEqual(ingest_data["status"], "PROCESSED")
                    self.assertEqual(ingest_data["attack_type"], "PortScan")
                    incident_id = ingest_data["incident_id"]

                    # 2. Query Incidents list
                    resp_incidents = await client.get("/api/incidents?limit=10")
                    self.assertEqual(resp_incidents.status_code, 200)
                    inc_list = resp_incidents.json()
                    self.assertTrue(inc_list["count"] >= 1)

                    # 3. Query Specific Incident Detail
                    resp_detail = await client.get(f"/api/incidents/{incident_id}")
                    self.assertEqual(resp_detail.status_code, 200)
                    detail_data = resp_detail.json()
                    self.assertEqual(detail_data["incident_id"], incident_id)

        self._run_async(_test())

    def test_blocks_and_manual_unblock(self):
        async def _test():
            async with lifespan(app):
                async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                    # Ingest critical DDoS flow to create block rule
                    flow_payload = {
                        "src_ip": "198.51.100.88",
                        "dst_ip": "192.168.1.10",
                        "src_port": 40000,
                        "dst_port": 80,
                        "protocol": 6,
                        "flow_duration": 1.0,
                        "tot_fwd_pkts": 1000,
                        "tot_bwd_pkts": 0,
                        "fwd_pkt_len_mean": 1200.0,
                        "bwd_pkt_len_mean": 0.0,
                        "flow_bytes_s": 500000.0,
                        "flow_pkts_s": 5000.0,
                        "syn_flag_count": 50,
                        "ack_flag_count": 0,
                        "rst_flag_count": 0
                    }
                    resp_ingest = await client.post("/api/flows/ingest", json=flow_payload)
                    self.assertEqual(resp_ingest.status_code, 200)
                    
                    # Query Blocks list
                    resp_blocks = await client.get("/api/blocks")
                    self.assertEqual(resp_blocks.status_code, 200)
                    blocks_data = resp_blocks.json()
                    self.assertTrue(blocks_data["count"] >= 1)
                    
                    rule_id = blocks_data["blocked_ips"][0]["rule_id"]
                    
                    # Test Manual Unblock
                    resp_unblock = await client.post(f"/api/blocks/unblock/{rule_id}")
                    self.assertEqual(resp_unblock.status_code, 200)
                    self.assertEqual(resp_unblock.json()["status"], "SUCCESS")

        self._run_async(_test())

    def test_report_generation_and_download(self):
        async def _test():
            async with lifespan(app):
                async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                    resp_gen = await client.post("/api/reports/generate")
                    self.assertEqual(resp_gen.status_code, 200)
                    gen_data = resp_gen.json()
                    self.assertEqual(gen_data["status"], "GENERATED")
                    filename = gen_data["filename"]

                    # Download report
                    resp_dl = await client.get(f"/api/reports/download/{filename}")
                    self.assertEqual(resp_dl.status_code, 200)
                    self.assertEqual(resp_dl.headers["content-type"], "application/pdf")

        self._run_async(_test())


if __name__ == "__main__":
    unittest.main()
