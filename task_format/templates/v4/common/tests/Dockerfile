# Separate verifier image (Harbor v0.25 tests/Dockerfile). Harbor builds it from tests/ and
# does not upload tests/ at runtime, so everything the verifier needs is baked in here.
# The grader itself (/opt/grader/grade) comes from the sast-grader base image; see
# ng-sast-agent/grader_image/README.md for the tag policy. Locally, `grader_image/build.sh`
# produces this exact tag, and Harbor's build (no --pull) uses it without registry access.
FROM us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:3

COPY test.sh ground_truth.json evaluator_view.json /tests/
